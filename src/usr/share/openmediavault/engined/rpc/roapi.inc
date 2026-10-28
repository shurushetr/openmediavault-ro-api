<?php
/**
 * Backend engine RPC service for openmediavault-ro-api.
 *
 * @license   https://www.gnu.org/licenses/gpl-3.0.html GPL Version 3
 * @author    shurushetr <shurushetr@gmail.com>
 * @copyright Copyright (c) 2026 shurushetr
 *
 * Enforces read-only queries, granular UI-controlled data scopes, subnet allowlisting,
 * timing-safe token validation, optional Infisical Universal Auth secret sync,
 * server-side secret redaction, native OMV log viewer integration, and
 * structured agentic feedback / self-diagnostics.
 */
class OMVRpcServiceRoApi extends \OMV\Rpc\ServiceAbstract
{
    private const PLUGIN_VERSION = "1.0.0-1";
    private const CACHE_FILE = "/run/openmediavault-ro-api.cache";
    private const STATUS_FILE = "/run/openmediavault-ro-api.status.json";
    private const LOG_FILE = "/var/log/openmediavault-ro-api.log";
    private const MAX_LOG_BYTES = 1048576; // 1 MiB

    private array $subRpcErrors = [];
    private string $currentClientIp = "127.0.0.1";
    private string $currentAuditMode = "errors_only";

    public function getName()
    {
        return "RoApi";
    }

    public function initialize()
    {
        $this->registerMethod("get");
        $this->registerMethod("set");
        $this->registerMethod("query");
    }

    public function get($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_ADMINISTRATOR
        ]);
        $db = \OMV\Config\Database::getInstance();
        $cfg = $db->getAssoc("conf.service.roapi");
        if (!array_key_exists("allow_logs", $cfg)) {
            $cfg["allow_logs"] = true;
        }
        if (!array_key_exists("allow_diagnostics", $cfg)) {
            $cfg["allow_diagnostics"] = true;
        }
        return $cfg;
    }

    public function set($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_ADMINISTRATOR
        ]);
        $this->validateMethodParams($params, "rpc.roapi.set");

        $db = \OMV\Config\Database::getInstance();
        $object = $db->get("conf.service.roapi");

        $regenerated = false;
        if (!empty($params['regeneratetoken']) || empty(trim((string)($params['apitoken'] ?? '')))) {
            $params['apitoken'] = bin2hex(random_bytes(32));
            $regenerated = true;
        }
        $params['regeneratetoken'] = false;

        $object->setAssoc($params);
        $db->set($object);
        @unlink(self::CACHE_FILE);

        $this->currentAuditMode = (string)($params['auditlog'] ?? 'errors_only');
        $this->logEvent(
            "INFO",
            "config",
            "127.0.0.1",
            sprintf(
                "Configuration updated via Workbench UI (enable=%s, token_regenerated=%s, infisical=%s, auditlog=%s)",
                !empty($params['enable']) ? "true" : "false",
                $regenerated ? "true" : "false",
                !empty($params['infisicalenable']) ? "true" : "false",
                $this->currentAuditMode
            )
        );

        return $object->getAssoc();
    }

    public function query($params, $context)
    {
        $startTime = microtime(true);
        $this->subRpcErrors = [];

        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_ADMINISTRATOR
        ]);
        $this->validateMethodParams($params, "rpc.roapi.query");

        $db = \OMV\Config\Database::getInstance();
        $cfg = $db->getAssoc("conf.service.roapi");

        $this->currentAuditMode = (string)($cfg['auditlog'] ?? 'errors_only');
        $failDelayMs = max(0, min(5000, (int)($cfg['faildelayms'] ?? 200)));
        $clientIp = $this->normalizeIp((string)($params['_client_ip'] ?? '127.0.0.1'));
        $this->currentClientIp = $clientIp;

        if (empty($cfg['enable'])) {
            $this->logEvent("WARNING", "access", $clientIp, "Rejected request: Read-Only API is disabled in UI settings.");
            throw new \OMV\HttpErrorException(
                403,
                "Read-Only API is disabled. Enable it in the OpenMediaVault Web UI under Services -> Read-Only API."
            );
        }

        $allowedIps = trim((string)($cfg['allowedips'] ?? '127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16'));
        if (!$this->isIpAllowed($clientIp, $allowedIps)) {
            if ($failDelayMs > 0) {
                usleep($failDelayMs * 1000);
            }
            $this->logEvent(
                "WARNING",
                "access",
                $clientIp,
                sprintf("Rejected request from unauthorized client IP '%s' (allowedips='%s')", $clientIp, $allowedIps)
            );
            throw new \OMV\HttpErrorException(
                403,
                sprintf("Client IP '%s' is not permitted by the Read-Only API allowedips policy.", $clientIp)
            );
        }

        $expectedToken = $this->resolveExpectedToken($cfg);
        $providedToken = trim((string)($params['token'] ?? ''));
        if (strlen($expectedToken) < 24 || !hash_equals($expectedToken, $providedToken)) {
            if ($failDelayMs > 0) {
                usleep($failDelayMs * 1000);
            }
            $this->logEvent("ALERT", "auth", $clientIp, "Invalid Read-Only API token attempt.");
            throw new \OMV\HttpErrorException(
                401,
                "Invalid Read-Only API token. Verify OMV_RO_API_TOKEN matches the token configured in Services -> Read-Only API (or Infisical)."
            );
        }

        $section = strtolower(trim((string)($params['section'] ?? 'overview')));
        $adminCtx = $this->getAdminContext();

        switch ($section) {
            case "overview":
            case "system":
                $this->assertScopeEnabled($cfg, "allow_overview", "overview");
                $data = $this->collectOverview($adminCtx);
                break;
            case "disks":
            case "smart":
            case "disks_and_smart":
                $this->assertScopeEnabled($cfg, "allow_disks", "disks_and_smart");
                $deviceFile = trim((string)($params['devicefile'] ?? ''));
                $data = $this->collectDisksAndSmart($adminCtx, $deviceFile);
                break;
            case "storage":
            case "filesystems":
            case "storage_and_filesystems":
                $this->assertScopeEnabled($cfg, "allow_storage", "storage_and_filesystems");
                $data = $this->collectStorageAndFilesystems($adminCtx);
                break;
            case "shares":
            case "exports":
            case "shares_and_exports":
                $this->assertScopeEnabled($cfg, "allow_shares", "shares_and_exports");
                $data = $this->collectSharesAndExports($adminCtx);
                break;
            case "ups":
            case "nut":
            case "power":
            case "ups_and_power":
                $this->assertScopeEnabled($cfg, "allow_ups", "ups_and_power");
                $data = $this->collectUpsAndPower($adminCtx);
                break;
            case "network":
            case "services":
            case "network_and_services":
                $this->assertScopeEnabled($cfg, "allow_network", "network_and_services");
                $data = $this->collectNetworkAndServices($adminCtx);
                break;
            case "apt":
            case "plugins":
            case "apt_and_plugins":
                $this->assertScopeEnabled($cfg, "allow_apt", "apt_and_plugins");
                $data = $this->collectAptAndPlugins($adminCtx);
                break;
            case "config":
            case "config_xml":
                $this->assertScopeEnabled($cfg, "allow_configxml", "config_xml");
                $data = $this->collectRedactedConfigXml();
                break;
            case "logs":
            case "log":
            case "system_logs":
                $this->assertScopeEnabled($cfg, "allow_logs", "logs");
                $logFile = strtolower(trim((string)($params['logfile'] ?? 'roapi')));
                $limit = max(1, min(500, (int)($params['limit'] ?? 100)));
                $data = $this->collectLogs($adminCtx, $logFile, $limit);
                break;
            case "diagnostics":
            case "diag":
            case "feedback":
            case "health":
                $this->assertScopeEnabled($cfg, "allow_diagnostics", "diagnostics");
                $limit = max(1, min(500, (int)($params['limit'] ?? 100)));
                $data = $this->collectDiagnostics($adminCtx, $cfg, $clientIp, $limit);
                break;
            case "all":
                $data = [];
                if (!empty($cfg['allow_overview'])) {
                    $data["overview"] = $this->collectOverview($adminCtx);
                }
                if (!empty($cfg['allow_disks'])) {
                    $data["disks_and_smart"] = $this->collectDisksAndSmart($adminCtx, "");
                }
                if (!empty($cfg['allow_storage'])) {
                    $data["storage_and_filesystems"] = $this->collectStorageAndFilesystems($adminCtx);
                }
                if (!empty($cfg['allow_shares'])) {
                    $data["shares_and_exports"] = $this->collectSharesAndExports($adminCtx);
                }
                if (!empty($cfg['allow_ups'])) {
                    $data["ups_and_power"] = $this->collectUpsAndPower($adminCtx);
                }
                if (!empty($cfg['allow_network'])) {
                    $data["network_and_services"] = $this->collectNetworkAndServices($adminCtx);
                }
                if (!empty($cfg['allow_apt'])) {
                    $data["apt_and_plugins"] = $this->collectAptAndPlugins($adminCtx);
                }
                if (!array_key_exists('allow_diagnostics', $cfg) || !empty($cfg['allow_diagnostics'])) {
                    $data["diagnostics"] = $this->collectDiagnostics($adminCtx, $cfg, $clientIp, 50);
                }
                break;
            default:
                $this->logEvent("WARNING", "access", $clientIp, sprintf("Unsupported section requested: '%s'", $section));
                throw new \OMV\HttpErrorException(
                    400,
                    sprintf(
                        "Unsupported read-only section '%s'. Valid sections: overview, disks, storage, shares, ups, network, apt, config_xml, logs, diagnostics, all.",
                        $section
                    )
                );
        }

        $durationMs = round((microtime(true) - $startTime) * 1000, 2);
        $scopeSummary = $this->getScopeSummary($cfg);
        $errCount = count($this->subRpcErrors);

        $hint = "All sub-RPC calls succeeded.";
        if ($errCount > 0) {
            $hint = sprintf(
                "%d sub-RPC call(s) reported partial errors. Call section='logs' (or omv_get_logs) and section='diagnostics' (or omv_get_diagnostics) to inspect daemon/plugin logs.",
                $errCount
            );
        }

        $data["_agent_feedback"] = [
            "plugin_version" => self::PLUGIN_VERSION,
            "section" => $section,
            "client_ip" => $clientIp,
            "timestamp" => date("c"),
            "duration_ms" => $durationMs,
            "partial_errors_count" => $errCount,
            "partial_errors" => $this->subRpcErrors,
            "enabled_scopes" => $scopeSummary["enabled"],
            "disabled_scopes" => $scopeSummary["disabled"],
            "troubleshooting_hint" => $hint,
        ];

        if ($this->currentAuditMode === 'all' || $errCount > 0) {
            $this->logEvent(
                $errCount > 0 ? "WARNING" : "INFO",
                "query",
                $clientIp,
                sprintf(
                    "Authorized query section='%s' duration=%.2fms partial_errors=%d",
                    $section,
                    $durationMs,
                    $errCount
                ),
                $this->currentAuditMode === 'all' || $errCount > 0
            );
        }

        $patterns = $this->parseRedactPatterns((string)($cfg['redactpatterns'] ?? ''));
        return $this->redactSecrets($data, $patterns);
    }

    private function getScopeSummary(array $cfg): array
    {
        $map = [
            "overview" => "allow_overview",
            "disks" => "allow_disks",
            "storage" => "allow_storage",
            "shares" => "allow_shares",
            "ups" => "allow_ups",
            "network" => "allow_network",
            "apt" => "allow_apt",
            "config_xml" => "allow_configxml",
            "logs" => "allow_logs",
            "diagnostics" => "allow_diagnostics",
        ];
        $enabled = [];
        $disabled = [];
        foreach ($map as $scope => $key) {
            if (!array_key_exists($key, $cfg) || !empty($cfg[$key])) {
                $enabled[] = $scope;
            } else {
                $disabled[] = $scope;
            }
        }
        return ["enabled" => $enabled, "disabled" => $disabled, "map" => $map];
    }

    private function assertScopeEnabled(array $cfg, string $flagKey, string $scopeName): void
    {
        if (array_key_exists($flagKey, $cfg) && empty($cfg[$flagKey])) {
            $summary = $this->getScopeSummary($cfg);
            $this->logEvent(
                "WARNING",
                "access",
                $this->currentClientIp,
                sprintf("Blocked query to disabled scope '%s' (flag %s=false)", $scopeName, $flagKey)
            );
            throw new \OMV\HttpErrorException(
                403,
                sprintf(
                    "Read-Only scope '%s' (%s) is disabled in OpenMediaVault Read-Only API settings (Services -> Read-Only API). Currently enabled scopes: [%s].",
                    $scopeName,
                    $flagKey,
                    implode(", ", $summary["enabled"])
                )
            );
        }
    }

    private function parseRedactPatterns(string $raw): array
    {
        $defaults = [
            "password",
            "passwd",
            "secret",
            "token",
            "apitoken",
            "privatekey",
            "passphrase",
            "shadow",
            "psk",
            "key",
        ];
        foreach (explode(",", $raw) as $part) {
            $p = strtolower(trim($part));
            if ($p !== "" && !in_array($p, $defaults, true)) {
                $defaults[] = $p;
            }
        }
        return $defaults;
    }

    private function safeRpc(string $service, string $method, $params, array $context)
    {
        $t0 = microtime(true);
        try {
            return \OMV\Rpc\Rpc::call($service, $method, $params, $context);
        } catch (\Throwable $e) {
            $elapsed = round((microtime(true) - $t0) * 1000, 2);
            $msg = $e->getMessage();
            $this->subRpcErrors[] = [
                "rpc" => $service . "::" . $method,
                "error" => $msg,
                "latency_ms" => $elapsed,
            ];
            $this->logEvent(
                "WARNING",
                "rpc",
                $this->currentClientIp,
                sprintf("Sub-RPC %s::%s failed after %.2fms: %s", $service, $method, $elapsed, $msg)
            );
            return [
                "_error" => $msg,
                "_rpc" => $service . "::" . $method,
            ];
        }
    }

    private function collectOverview(array $ctx): array
    {
        return [
            "system_info" => $this->safeRpc("System", "getInformation", null, $ctx),
            "time_settings" => $this->safeRpc("System", "getTimeSettings", null, $ctx),
            "config_dirty" => $this->safeRpc("Config", "isDirty", null, $ctx),
            "services_status" => $this->safeRpc("Services", "getStatus", null, $ctx),
            "webgui_settings" => $this->safeRpc("WebGui", "getSettings", null, $ctx),
            "ssh_settings" => $this->safeRpc("SSH", "get", null, $ctx),
        ];
    }

    private function collectDisksAndSmart(array $ctx, string $deviceFile): array
    {
        $disks = $this->safeRpc("DiskMgmt", "enumerateDevices", null, $ctx);
        $smartSettings = $this->safeRpc("Smart", "getSettings", null, $ctx);
        $smartList = $this->safeRpc("Smart", "getList", ["start" => 0, "limit" => -1], $ctx);

        $details = [];
        if ($deviceFile !== "") {
            $details[$deviceFile] = [
                "info" => $this->safeRpc("Smart", "getInformation", ["devicefile" => $deviceFile], $ctx),
                "attributes" => $this->safeRpc("Smart", "getAttributes", ["devicefile" => $deviceFile], $ctx),
                "selftest_logs" => $this->safeRpc("Smart", "getSelfTestLogs", ["devicefile" => $deviceFile], $ctx),
            ];
        } elseif (is_array($disks) && !isset($disks['_error'])) {
            foreach ($disks as $disk) {
                $dev = $disk['devicefile'] ?? '';
                if ($dev !== '' && strpos($dev, '/dev/loop') !== 0 && strpos($dev, '/dev/ram') !== 0) {
                    $details[$dev] = [
                        "info" => $this->safeRpc("Smart", "getInformation", ["devicefile" => $dev], $ctx),
                        "attributes" => $this->safeRpc("Smart", "getAttributes", ["devicefile" => $dev], $ctx),
                    ];
                }
            }
        }

        return [
            "disks" => $disks,
            "smart_settings" => $smartSettings,
            "smart_overview" => $smartList,
            "smart_schedules" => $this->safeRpc("Smart", "getScheduleList", ["start" => 0, "limit" => -1], $ctx),
            "smart_details" => $details,
        ];
    }

    private function collectStorageAndFilesystems(array $ctx): array
    {
        $mdstat = is_readable("/proc/mdstat") ? @file_get_contents("/proc/mdstat") : null;
        $zpoolStatus = null;
        if (is_executable("/sbin/zpool") || is_executable("/usr/sbin/zpool")) {
            $out = [];
            @exec("zpool status 2>&1", $out, $rc);
            if ($rc === 0) {
                $zpoolStatus = implode("\n", $out);
            }
        }
        return [
            "filesystems" => $this->safeRpc("FileSystemMgmt", "enumerateFilesystems", null, $ctx),
            "mounted_filesystems" => $this->safeRpc("FileSystemMgmt", "enumerateMountedFilesystems", ["includeroot" => true], $ctx),
            "fstab_entries" => $this->safeRpc("FsTab", "enumerateEntries", null, $ctx),
            "proc_mdstat" => $mdstat,
            "zpool_status" => $zpoolStatus,
        ];
    }

    private function collectSharesAndExports(array $ctx): array
    {
        return [
            "shared_folders" => $this->safeRpc("ShareMgmt", "enumerateSharedFolders", null, $ctx),
            "snapshots" => $this->safeRpc("ShareMgmt", "enumerateAllSnapshots", null, $ctx),
            "smb_settings" => $this->safeRpc("SMB", "getSettings", null, $ctx),
            "smb_shares" => $this->safeRpc("SMB", "getShareList", ["start" => 0, "limit" => -1], $ctx),
            "nfs_settings" => $this->safeRpc("NFS", "getSettings", null, $ctx),
            "nfs_shares" => $this->safeRpc("NFS", "getShareList", ["start" => 0, "limit" => -1], $ctx),
        ];
    }

    private function collectUpsAndPower(array $ctx): array
    {
        $nutFiles = [];
        foreach (["/etc/nut/nut.conf", "/etc/nut/ups.conf", "/etc/nut/upsd.conf", "/etc/nut/upsmon.conf", "/etc/nut/upssched.conf"] as $path) {
            if (is_readable($path)) {
                $lines = @file($path, FILE_IGNORE_NEW_LINES) ?: [];
                $filtered = [];
                foreach ($lines as $line) {
                    $trimmed = trim($line);
                    if ($trimmed === "" || strpos($trimmed, "#") === 0) {
                        continue;
                    }
                    $line = preg_replace('/^(MONITOR\s+\S+\s+\S+\s+\S+\s+)\S+(\s+.+)$/i', '$1***REDACTED***$2', $line);
                    $line = preg_replace('/^(\s*password\s*=\s*).*$/i', '$1***REDACTED***', $line);
                    $filtered[] = $line;
                }
                $nutFiles[$path] = $filtered;
            }
        }

        $omvDefaultNut = [];
        if (is_readable("/etc/default/openmediavault")) {
            foreach (@file("/etc/default/openmediavault", FILE_IGNORE_NEW_LINES) ?: [] as $line) {
                if (strpos(trim($line), "OMV_NUT_") === 0) {
                    $omvDefaultNut[] = $line;
                }
            }
        }

        return [
            "nut_config" => $this->safeRpc("Nut", "get", null, $ctx),
            "nut_stats" => $this->safeRpc("Nut", "getStats", null, $ctx),
            "nut_files" => $nutFiles,
            "omv_default_nut_env" => $omvDefaultNut,
            "power_mgmt" => $this->safeRpc("PowerMgmt", "get", null, $ctx),
            "power_schedules" => $this->safeRpc("PowerMgmt", "getScheduleList", ["start" => 0, "limit" => -1], $ctx),
            "cron_jobs" => $this->safeRpc("Cron", "getList", [
                "start" => 0,
                "limit" => -1,
                "type" => ["userdefined", "reboot", "powermanagement"]
            ], $ctx),
        ];
    }

    private function collectNetworkAndServices(array $ctx): array
    {
        return [
            "general" => $this->safeRpc("Network", "getGeneralSettings", null, $ctx),
            "interfaces" => $this->safeRpc("Network", "enumerateDevicesList", ["start" => 0, "limit" => -1], $ctx),
            "proxy" => $this->safeRpc("Network", "getProxy", null, $ctx),
            "services" => $this->safeRpc("Services", "getStatus", null, $ctx),
            "ssl_certificates" => $this->safeRpc("CertificateMgmt", "getList", ["start" => 0, "limit" => -1], $ctx),
            "ssh_certificates" => $this->safeRpc("CertificateMgmt", "getSshList", ["start" => 0, "limit" => -1], $ctx),
        ];
    }

    private function collectAptAndPlugins(array $ctx): array
    {
        $plugins = $this->safeRpc("Plugin", "enumeratePlugins", null, $ctx);
        $installedPlugins = [];
        if (is_array($plugins) && !isset($plugins['_error'])) {
            foreach ($plugins as $pkg) {
                if (!empty($pkg['installed'])) {
                    $installedPlugins[] = [
                        "name" => $pkg['name'] ?? '',
                        "version" => $pkg['version'] ?? '',
                        "summary" => $pkg['summary'] ?? ($pkg['abstract'] ?? ''),
                        "pluginsection" => $pkg['pluginsection'] ?? '',
                    ];
                }
            }
        }
        return [
            "software_settings" => $this->safeRpc("Apt", "getSoftwareSettings", null, $ctx),
            "updates_settings" => $this->safeRpc("Apt", "getUpdatesSettings", null, $ctx),
            "upgradable_packages" => $this->safeRpc("Apt", "enumerateUpgraded", null, $ctx),
            "installed_plugins" => $installedPlugins,
        ];
    }

    private function collectRedactedConfigXml(): array
    {
        $xmlFile = \OMV\Environment::get("OMV_CONFIG_FILE", "/etc/openmediavault/config.xml");
        if (!is_readable($xmlFile)) {
            return ["_error" => "Cannot read config.xml"];
        }
        $raw = @file_get_contents($xmlFile);
        if ($raw === false) {
            return ["_error" => "Failed to read config.xml"];
        }
        $xml = @simplexml_load_string($raw, "SimpleXMLElement", LIBXML_NOCDATA);
        if ($xml === false) {
            return ["_error" => "Failed to parse config.xml"];
        }
        $arr = json_decode(json_encode($xml), true);
        return is_array($arr) ? $arr : [];
    }

    /**
     * Collect system, daemon, or Read-Only API logs for agentic troubleshooting.
     */
    private function collectLogs(array $ctx, string $logFile, int $limit): array
    {
        $availableSources = [
            "roapi" => "OpenMediaVault Read-Only API plugin audit & diagnostic log (/var/log/openmediavault-ro-api.log)",
            "syslog" => "Debian / OpenMediaVault system log (LogFile::getList id=syslog)",
            "daemon" => "System daemon log (LogFile::getList id=daemon)",
            "messages" => "Kernel / system messages (LogFile::getList id=messages)",
            "auth" => "Authentication log (LogFile::getList id=auth)",
            "smartd" => "S.M.A.R.T. disk monitoring daemon log (LogFile::getList id=smartd)",
            "smb" => "Samba SMB/CIFS daemon log",
            "rsync" => "Rsync service log",
            "nut" => "Network UPS Tools systemd journal (nut-server, nut-monitor, nut-driver)",
            "engined" => "OpenMediaVault backend engine journal (openmediavault-engined)",
            "nginx" => "NGINX web server journal & error log",
            "nfs" => "NFS server systemd journal (nfs-server)",
        ];

        $journalUnitMap = [
            "nut" => ["nut-server.service", "nut-monitor.service", "nut-driver@ups.service", "nut-driver.target"],
            "engined" => ["openmediavault-engined.service"],
            "nginx" => ["nginx.service"],
            "nfs" => ["nfs-server.service", "nfs-mountd.service"],
            "smartd" => ["smartmontools.service", "smartd.service"],
            "smb" => ["smbd.service", "nmbd.service"],
        ];

        if ($logFile === "" || $logFile === "roapi") {
            return [
                "requested_source" => "roapi",
                "available_sources" => $availableSources,
                "entries" => $this->readRoApiLogEntries($limit),
            ];
        }

        if (isset($journalUnitMap[$logFile])) {
            $entries = $this->readJournalUnits($journalUnitMap[$logFile], $limit);
            return [
                "requested_source" => $logFile,
                "available_sources" => $availableSources,
                "units" => $journalUnitMap[$logFile],
                "entries" => $entries,
            ];
        }

        $omvLogIds = ["syslog", "daemon", "messages", "auth", "boot", "dmesg", "smartd", "rsync", "proftpd"];
        if (in_array($logFile, $omvLogIds, true)) {
            $res = $this->safeRpc("LogFile", "getList", [
                "id" => $logFile,
                "start" => 0,
                "limit" => $limit,
                "sortfield" => "ts",
                "sortdir" => "DESC",
            ], $ctx);
            if (is_array($res) && isset($res['data']) && is_array($res['data'])) {
                $res['data'] = array_map([$this, "sanitizeLogEntry"], $res['data']);
            }
            return [
                "requested_source" => $logFile,
                "available_sources" => $availableSources,
                "logfile_result" => $res,
            ];
        }

        return [
            "requested_source" => $logFile,
            "error" => sprintf("Unknown log source '%s'.", $logFile),
            "available_sources" => $availableSources,
        ];
    }

    /**
     * Collect comprehensive self-diagnostics, scope matrix, Infisical sync health,
     * sub-RPC latency probes, and recent plugin events for AI agent feedback.
     */
    private function collectDiagnostics(array $ctx, array $cfg, string $clientIp, int $limit): array
    {
        $scopeSummary = $this->getScopeSummary($cfg);

        $cacheTtl = max(10, min(86400, (int)($cfg['infisicalcachettl'] ?? 300)));
        $cacheInfo = [
            "cache_file" => self::CACHE_FILE,
            "exists" => false,
            "age_seconds" => null,
            "ttl_seconds" => $cacheTtl,
            "valid" => false,
        ];
        if (is_readable(self::CACHE_FILE)) {
            $cached = @json_decode(@file_get_contents(self::CACHE_FILE), true);
            if (is_array($cached) && isset($cached['ts'])) {
                $age = time() - (int)$cached['ts'];
                $cacheInfo["exists"] = true;
                $cacheInfo["age_seconds"] = $age;
                $cacheInfo["valid"] = !empty($cached['token']) && ($age < $cacheTtl);
            }
        }

        $lastInfisicalStatus = [
            "status" => !empty($cfg['infisicalenable']) ? "not_yet_synced" : "disabled",
            "timestamp" => null,
            "http_code" => null,
            "message" => !empty($cfg['infisicalenable'])
                ? "Infisical Universal Auth is enabled; no sync recorded in this runtime yet."
                : "Infisical Universal Auth sync is disabled (using static Read-Only API token).",
        ];
        if (is_readable(self::STATUS_FILE)) {
            $st = @json_decode(@file_get_contents(self::STATUS_FILE), true);
            if (is_array($st)) {
                $lastInfisicalStatus = array_merge($lastInfisicalStatus, $st);
            }
        }

        $probes = [
            ["service" => "System", "method" => "getInformation", "params" => null],
            ["service" => "Config", "method" => "isDirty", "params" => null],
            ["service" => "Services", "method" => "getStatus", "params" => null],
            ["service" => "DiskMgmt", "method" => "enumerateDevices", "params" => null],
            ["service" => "Smart", "method" => "getSettings", "params" => null],
            ["service" => "FileSystemMgmt", "method" => "enumerateMountedFilesystems", "params" => ["includeroot" => true]],
            ["service" => "ShareMgmt", "method" => "enumerateSharedFolders", "params" => null],
            ["service" => "Nut", "method" => "get", "params" => null],
            ["service" => "Network", "method" => "getGeneralSettings", "params" => null],
            ["service" => "Plugin", "method" => "enumeratePlugins", "params" => null],
        ];
        $probeResults = [];
        foreach ($probes as $p) {
            $t0 = microtime(true);
            $rpcName = $p["service"] . "::" . $p["method"];
            try {
                \OMV\Rpc\Rpc::call($p["service"], $p["method"], $p["params"], $ctx);
                $probeResults[$rpcName] = [
                    "status" => "ok",
                    "latency_ms" => round((microtime(true) - $t0) * 1000, 2),
                ];
            } catch (\Throwable $e) {
                $probeResults[$rpcName] = [
                    "status" => "error",
                    "latency_ms" => round((microtime(true) - $t0) * 1000, 2),
                    "error" => $e->getMessage(),
                ];
            }
        }

        $patterns = $this->parseRedactPatterns((string)($cfg['redactpatterns'] ?? ''));

        return [
            "plugin_info" => [
                "package" => "openmediavault-ro-api",
                "version" => self::PLUGIN_VERSION,
                "php_version" => PHP_VERSION,
                "server_time" => date("c"),
                "client_ip_detected" => $clientIp,
                "allowed_ips_policy" => (string)($cfg['allowedips'] ?? ''),
                "audit_log_mode" => (string)($cfg['auditlog'] ?? 'errors_only'),
                "fail_delay_ms" => (int)($cfg['faildelayms'] ?? 200),
                "redact_patterns_active" => $patterns,
                "log_file_path" => self::LOG_FILE,
                "log_file_writable" => is_writable(self::LOG_FILE) || is_writable(dirname(self::LOG_FILE)),
            ],
            "scope_permissions" => [
                "enabled_scopes" => $scopeSummary["enabled"],
                "disabled_scopes" => $scopeSummary["disabled"],
            ],
            "infisical_sync" => [
                "enabled" => !empty($cfg['infisicalenable']),
                "url" => (string)($cfg['infisicalurl'] ?? 'https://app.infisical.com'),
                "project_id_configured" => trim((string)($cfg['infisicalprojectid'] ?? '')) !== "",
                "project_id" => (string)($cfg['infisicalprojectid'] ?? ''),
                "environment" => (string)($cfg['infisicalenv'] ?? 'prod'),
                "secret_path" => (string)($cfg['infisicalpath'] ?? '/omv'),
                "secret_key" => (string)($cfg['infisicalsecretkey'] ?? 'OMV_RO_API_TOKEN'),
                "client_credentials_configured" => (
                    trim((string)($cfg['infisicalclientid'] ?? '')) !== "" &&
                    trim((string)($cfg['infisicalclientsecret'] ?? '')) !== ""
                ),
                "verify_ssl" => !array_key_exists('infisicalverifyssl', $cfg) || !empty($cfg['infisicalverifyssl']),
                "fallback_to_static_token" => !empty($cfg['infisicalfallback']),
                "cache" => $cacheInfo,
                "last_sync_result" => $lastInfisicalStatus,
            ],
            "omv_sub_rpc_health_probes" => $probeResults,
            "recent_roapi_logs" => $this->readRoApiLogEntries($limit),
        ];
    }

    private function readRoApiLogEntries(int $limit): array
    {
        if (!is_readable(self::LOG_FILE)) {
            return [];
        }
        $lines = @file(self::LOG_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        $slice = array_slice($lines, -$limit);
        $slice = array_reverse($slice);
        $entries = [];
        foreach ($slice as $line) {
            $line = $this->sanitizeLogString($line);
            if (preg_match('/^(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+(\S+)\s+(.*)$/', $line, $m)) {
                $entries[] = [
                    "timestamp" => $m[1],
                    "ts" => strtotime($m[1]) ?: null,
                    "level" => $m[2],
                    "component" => $m[3],
                    "client_ip" => $m[4],
                    "message" => $m[5],
                ];
            } else {
                $entries[] = [
                    "raw" => $line,
                ];
            }
        }
        return $entries;
    }

    private function readJournalUnits(array $units, int $limit): array
    {
        $cmdParts = ["journalctl", "--no-pager", "-o", "short-iso", "-n", (string)$limit];
        foreach ($units as $u) {
            $cmdParts[] = "-u";
            $cmdParts[] = escapeshellarg($u);
        }
        $cmd = implode(" ", $cmdParts) . " 2>&1";
        $out = [];
        @exec($cmd, $out, $rc);
        $cleaned = [];
        foreach ($out as $line) {
            $cleaned[] = $this->sanitizeLogString($line);
        }
        return $cleaned;
    }

    private function sanitizeLogEntry($entry)
    {
        if (is_array($entry)) {
            foreach ($entry as $k => $v) {
                if (is_string($v)) {
                    $entry[$k] = $this->sanitizeLogString($v);
                }
            }
            return $entry;
        }
        if (is_string($entry)) {
            return $this->sanitizeLogString($entry);
        }
        return $entry;
    }

    private function sanitizeLogString(string $line): string
    {
        $line = preg_replace('/((?:password|passwd|secret|token|apitoken|clientSecret)\s*[=:]\s*)[^\s"\',;]+/i', '$1***REDACTED***', $line);
        $line = preg_replace('/(Bearer\s+)[A-Za-z0-9._\-]+/i', '$1***REDACTED***', $line);
        return $line;
    }

    private function logEvent(string $level, string $component, string $clientIp, string $message, bool $forceSyslog = false): void
    {
        $cleanMsg = str_replace(["\r", "\n"], " ", $this->sanitizeLogString($message));
        $ip = $clientIp !== "" ? $clientIp : "127.0.0.1";
        $line = sprintf("%s %s [%s] %s %s\n", date("c"), strtoupper($level), $component, $ip, $cleanMsg);

        if (file_exists(self::LOG_FILE) && @filesize(self::LOG_FILE) > self::MAX_LOG_BYTES) {
            $existing = @file(self::LOG_FILE, FILE_IGNORE_NEW_LINES) ?: [];
            $kept = array_slice($existing, -500);
            @file_put_contents(self::LOG_FILE, implode("\n", $kept) . "\n", LOCK_EX);
        }
        @file_put_contents(self::LOG_FILE, $line, FILE_APPEND | LOCK_EX);

        if ($this->currentAuditMode === "off" && !$forceSyslog) {
            return;
        }
        if ($this->currentAuditMode === "errors_only" && $level === "INFO" && !$forceSyslog) {
            return;
        }
        $prio = LOG_INFO;
        if ($level === "ALERT") {
            $prio = LOG_ALERT;
        } elseif ($level === "WARNING" || $level === "ERROR") {
            $prio = LOG_WARNING;
        }
        @syslog($prio, sprintf("openmediavault-ro-api [%s] client=%s %s", $component, $ip, $cleanMsg));
    }

    private function recordInfisicalStatus(string $status, ?int $httpCode, string $message): void
    {
        $payload = [
            "status" => $status,
            "timestamp" => date("c"),
            "http_code" => $httpCode,
            "message" => $this->sanitizeLogString($message),
        ];
        @file_put_contents(self::STATUS_FILE, json_encode($payload), LOCK_EX);
        @chmod(self::STATUS_FILE, 0600);
    }

    private function redactSecrets($data, array $patterns)
    {
        if (is_array($data)) {
            $out = [];
            foreach ($data as $k => $v) {
                $kl = strtolower((string)$k);
                $shouldRedact = false;
                foreach ($patterns as $pat) {
                    if ($pat === "key" || $pat === "psk" || $pat === "token") {
                        if ($kl === $pat || substr($kl, -strlen($pat)) === $pat) {
                            $shouldRedact = true;
                            break;
                        }
                    } elseif (strpos($kl, $pat) !== false) {
                        $shouldRedact = true;
                        break;
                    }
                }
                if ($shouldRedact) {
                    $out[$k] = ($v !== "" && $v !== null) ? "***REDACTED***" : $v;
                } else {
                    $out[$k] = $this->redactSecrets($v, $patterns);
                }
            }
            return $out;
        }
        return $data;
    }

    private function normalizeIp(string $ip): string
    {
        $ip = trim($ip);
        if (stripos($ip, "::ffff:") === 0) {
            return substr($ip, 7);
        }
        return $ip;
    }

    private function isIpAllowed(string $clientIp, string $allowedList): bool
    {
        if ($allowedList === "*" || $clientIp === "127.0.0.1" || $clientIp === "::1") {
            return true;
        }
        if ($clientIp === "") {
            return false;
        }
        $clientLong = ip2long($clientIp);
        foreach (explode(",", $allowedList) as $entry) {
            $entry = trim($entry);
            if ($entry === "") {
                continue;
            }
            if ($entry === "*" || strcasecmp($entry, $clientIp) === 0) {
                return true;
            }
            if ($clientLong !== false && strpos($entry, "/") !== false) {
                [$subnet, $bits] = explode("/", $entry, 2);
                $subnetLong = ip2long(trim($subnet));
                $bits = (int)$bits;
                if ($subnetLong !== false && $bits >= 0 && $bits <= 32) {
                    $mask = $bits === 0 ? 0 : ((~0 << (32 - $bits)) & 0xFFFFFFFF);
                    if ((($clientLong & 0xFFFFFFFF) & $mask) === (($subnetLong & 0xFFFFFFFF) & $mask)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private function resolveExpectedToken(array $cfg): string
    {
        $localToken = trim((string)($cfg['apitoken'] ?? ''));
        if (empty($cfg['infisicalenable'])) {
            return $localToken;
        }

        $clientId = trim((string)($cfg['infisicalclientid'] ?? ''));
        $clientSecret = trim((string)($cfg['infisicalclientsecret'] ?? ''));
        if ($clientId === "" || $clientSecret === "") {
            $msg = "Infisical Universal Auth is enabled, but Client ID or Client Secret is empty.";
            $this->recordInfisicalStatus("missing_credentials", null, $msg);
            $this->logEvent("WARNING", "infisical", $this->currentClientIp, $msg);
            return !empty($cfg['infisicalfallback']) ? $localToken : "";
        }

        $cacheTtl = max(10, min(86400, (int)($cfg['infisicalcachettl'] ?? 300)));
        if (is_readable(self::CACHE_FILE)) {
            $cached = @json_decode(@file_get_contents(self::CACHE_FILE), true);
            if (
                is_array($cached) &&
                !empty($cached['token']) &&
                isset($cached['ts']) &&
                (time() - (int)$cached['ts']) < $cacheTtl
            ) {
                return (string)$cached['token'];
            }
        }

        $fetched = $this->fetchTokenFromInfisical($cfg);
        if ($fetched !== "") {
            @file_put_contents(
                self::CACHE_FILE,
                json_encode(["ts" => time(), "token" => $fetched]),
                LOCK_EX
            );
            @chmod(self::CACHE_FILE, 0600);
            return $fetched;
        }

        if (!empty($cfg['infisicalfallback']) && $localToken !== "") {
            $this->logEvent(
                "WARNING",
                "infisical",
                $this->currentClientIp,
                "Infisical token fetch failed; falling back to local static Read-Only API token."
            );
            return $localToken;
        }
        return "";
    }

    private function extractHttpCode($headers): ?int
    {
        if (!is_array($headers)) {
            return null;
        }
        foreach ($headers as $h) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#i', $h, $m)) {
                return (int)$m[1];
            }
        }
        return null;
    }

    private function fetchTokenFromInfisical(array $cfg): string
    {
        $baseUrl = rtrim(trim((string)($cfg['infisicalurl'] ?? 'https://app.infisical.com')), '/');
        $projectId = trim((string)($cfg['infisicalprojectid'] ?? ''));
        $envSlug = trim((string)($cfg['infisicalenv'] ?? 'prod'));
        $secretPath = trim((string)($cfg['infisicalpath'] ?? '/omv'));
        $secretKey = trim((string)($cfg['infisicalsecretkey'] ?? 'OMV_RO_API_TOKEN'));
        $clientId = trim((string)($cfg['infisicalclientid'] ?? ''));
        $clientSecret = trim((string)($cfg['infisicalclientsecret'] ?? ''));
        $verifySsl = !array_key_exists('infisicalverifyssl', $cfg) || !empty($cfg['infisicalverifyssl']);

        if ($baseUrl === "" || $projectId === "" || $clientId === "" || $clientSecret === "") {
            $msg = "Infisical configuration incomplete (baseUrl, projectId, clientId, or clientSecret missing).";
            $this->recordInfisicalStatus("config_incomplete", null, $msg);
            $this->logEvent("WARNING", "infisical", $this->currentClientIp, $msg);
            return "";
        }

        $sslOpts = [
            "verify_peer" => $verifySsl,
            "verify_peer_name" => $verifySsl,
        ];

        $loginUrl = $baseUrl . "/api/v1/auth/universal-auth/login";
        $loginCtx = stream_context_create([
            "http" => [
                "method" => "POST",
                "header" => "Content-Type: application/json\r\nAccept: application/json\r\n",
                "content" => json_encode([
                    "clientId" => $clientId,
                    "clientSecret" => $clientSecret,
                ]),
                "timeout" => 5,
                "ignore_errors" => true,
            ],
            "ssl" => $sslOpts,
        ]);
        $loginRaw = @file_get_contents($loginUrl, false, $loginCtx);
        $loginCode = $this->extractHttpCode($http_response_header ?? null);
        if ($loginRaw === false || ($loginCode !== null && $loginCode >= 400)) {
            $msg = sprintf(
                "Infisical Universal Auth login failed at %s (HTTP %s). Verify URL, TLS cert, Client ID, and Client Secret.",
                $loginUrl,
                $loginCode !== null ? (string)$loginCode : "connection_error"
            );
            $this->recordInfisicalStatus("auth_failed", $loginCode, $msg);
            $this->logEvent("WARNING", "infisical", $this->currentClientIp, $msg);
            return "";
        }
        $loginJson = @json_decode($loginRaw, true);
        $accessToken = $loginJson['accessToken'] ?? '';
        if ($accessToken === "") {
            $msg = sprintf("Infisical login response from %s did not contain accessToken.", $loginUrl);
            $this->recordInfisicalStatus("auth_failed", $loginCode, $msg);
            $this->logEvent("WARNING", "infisical", $this->currentClientIp, $msg);
            return "";
        }

        $query = http_build_query([
            "workspaceId" => $projectId,
            "environment" => $envSlug,
            "secretPath" => $secretPath,
        ]);
        $secretUrl = $baseUrl . "/api/v3/secrets/raw/" . rawurlencode($secretKey) . "?" . $query;
        $secCtx = stream_context_create([
            "http" => [
                "method" => "GET",
                "header" => "Authorization: Bearer " . $accessToken . "\r\nAccept: application/json\r\n",
                "timeout" => 5,
                "ignore_errors" => true,
            ],
            "ssl" => $sslOpts,
        ]);
        $secRaw = @file_get_contents($secretUrl, false, $secCtx);
        $secCode = $this->extractHttpCode($http_response_header ?? null);
        if ($secRaw === false || ($secCode !== null && $secCode >= 400)) {
            $msg = sprintf(
                "Infisical secret fetch failed for key='%s' path='%s' env='%s' project='%s' (HTTP %s).",
                $secretKey,
                $secretPath,
                $envSlug,
                $projectId,
                $secCode !== null ? (string)$secCode : "connection_error"
            );
            $this->recordInfisicalStatus("secret_fetch_failed", $secCode, $msg);
            $this->logEvent("WARNING", "infisical", $this->currentClientIp, $msg);
            return "";
        }
        $secJson = @json_decode($secRaw, true);
        $val = trim((string)($secJson['secret']['secretValue'] ?? ''));
        if ($val === "") {
            $msg = sprintf("Infisical secret '%s' at path '%s' was empty or missing secretValue field.", $secretKey, $secretPath);
            $this->recordInfisicalStatus("secret_empty", $secCode, $msg);
            $this->logEvent("WARNING", "infisical", $this->currentClientIp, $msg);
            return "";
        }

        $okMsg = sprintf(
            "Successfully synced secret '%s' from Infisical (env='%s', path='%s').",
            $secretKey,
            $envSlug,
            $secretPath
        );
        $this->recordInfisicalStatus("ok", $secCode ?? 200, $okMsg);
        if ($this->currentAuditMode === "all") {
            $this->logEvent("INFO", "infisical", $this->currentClientIp, $okMsg);
        }
        return $val;
    }
}
