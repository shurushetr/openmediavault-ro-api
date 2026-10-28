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
 * and server-side secret redaction.
 */
class OMVRpcServiceRoApi extends \OMV\Rpc\ServiceAbstract
{
    private const CACHE_FILE = "/run/openmediavault-ro-api.cache";

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
        return $db->getAssoc("conf.service.roapi");
    }

    public function set($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_ADMINISTRATOR
        ]);
        $this->validateMethodParams($params, "rpc.roapi.set");

        $db = \OMV\Config\Database::getInstance();
        $object = $db->get("conf.service.roapi");

        // Handle one-click token generation in the Workbench UI
        if (!empty($params['regeneratetoken']) || empty(trim((string)($params['apitoken'] ?? '')))) {
            $params['apitoken'] = bin2hex(random_bytes(32));
        }
        $params['regeneratetoken'] = false;

        $object->setAssoc($params);
        $db->set($object);
        @unlink(self::CACHE_FILE);
        return $object->getAssoc();
    }

    public function query($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_ADMINISTRATOR
        ]);
        $this->validateMethodParams($params, "rpc.roapi.query");

        $db = \OMV\Config\Database::getInstance();
        $cfg = $db->getAssoc("conf.service.roapi");

        if (empty($cfg['enable'])) {
            throw new \OMV\HttpErrorException(403, "Read-Only API is disabled.");
        }

        $auditMode = (string)($cfg['auditlog'] ?? 'errors_only');
        $failDelayMs = max(0, min(5000, (int)($cfg['faildelayms'] ?? 200)));

        $clientIp = $this->normalizeIp((string)($params['_client_ip'] ?? ''));
        $allowedIps = trim((string)($cfg['allowedips'] ?? '127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16'));
        if (!$this->isIpAllowed($clientIp, $allowedIps)) {
            if ($failDelayMs > 0) {
                usleep($failDelayMs * 1000);
            }
            if ($auditMode !== 'off') {
                syslog(LOG_WARNING, sprintf(
                    "openmediavault-ro-api: rejected request from unauthorized IP '%s'",
                    $clientIp
                ));
            }
            throw new \OMV\HttpErrorException(403, "Client IP is not permitted.");
        }

        $expectedToken = $this->resolveExpectedToken($cfg);
        $providedToken = trim((string)($params['token'] ?? ''));
        if (strlen($expectedToken) < 24 || !hash_equals($expectedToken, $providedToken)) {
            if ($failDelayMs > 0) {
                usleep($failDelayMs * 1000);
            }
            if ($auditMode !== 'off') {
                syslog(LOG_ALERT, sprintf(
                    "openmediavault-ro-api: invalid API token attempt from '%s'",
                    $clientIp
                ));
            }
            throw new \OMV\HttpErrorException(401, "Invalid Read-Only API token.");
        }

        $section = strtolower(trim((string)($params['section'] ?? 'overview')));
        if ($auditMode === 'all') {
            syslog(LOG_INFO, sprintf(
                "openmediavault-ro-api: authorized query section='%s' from '%s'",
                $section,
                $clientIp
            ));
        }

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
                break;
            default:
                throw new \OMV\HttpErrorException(
                    400,
                    sprintf("Unsupported read-only section '%s'.", $section)
                );
        }

        $patterns = $this->parseRedactPatterns((string)($cfg['redactpatterns'] ?? ''));
        return $this->redactSecrets($data, $patterns);
    }

    private function assertScopeEnabled(array $cfg, string $flagKey, string $scopeName): void
    {
        if (array_key_exists($flagKey, $cfg) && empty($cfg[$flagKey])) {
            throw new \OMV\HttpErrorException(
                403,
                sprintf("Read-Only scope '%s' is disabled in OpenMediaVault Read-Only API settings.", $scopeName)
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
        try {
            return \OMV\Rpc\Rpc::call($service, $method, $params, $context);
        } catch (\Throwable $e) {
            return ["_error" => $e->getMessage()];
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

        return !empty($cfg['infisicalfallback']) ? $localToken : "";
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
            return "";
        }

        $sslOpts = [
            "verify_peer" => $verifySsl,
            "verify_peer_name" => $verifySsl,
        ];

        $loginCtx = stream_context_create([
            "http" => [
                "method" => "POST",
                "header" => "Content-Type: application/json\r\nAccept: application/json\r\n",
                "content" => json_encode([
                    "clientId" => $clientId,
                    "clientSecret" => $clientSecret,
                ]),
                "timeout" => 5,
            ],
            "ssl" => $sslOpts,
        ]);
        $loginRaw = @file_get_contents($baseUrl . "/api/v1/auth/universal-auth/login", false, $loginCtx);
        if ($loginRaw === false) {
            return "";
        }
        $loginJson = @json_decode($loginRaw, true);
        $accessToken = $loginJson['accessToken'] ?? '';
        if ($accessToken === "") {
            return "";
        }

        $query = http_build_query([
            "workspaceId" => $projectId,
            "environment" => $envSlug,
            "secretPath" => $secretPath,
        ]);
        $secCtx = stream_context_create([
            "http" => [
                "method" => "GET",
                "header" => "Authorization: Bearer " . $accessToken . "\r\nAccept: application/json\r\n",
                "timeout" => 5,
            ],
            "ssl" => $sslOpts,
        ]);
        $secRaw = @file_get_contents(
            $baseUrl . "/api/v3/secrets/raw/" . rawurlencode($secretKey) . "?" . $query,
            false,
            $secCtx
        );
        if ($secRaw === false) {
            return "";
        }
        $secJson = @json_decode($secRaw, true);
        return trim((string)($secJson['secret']['secretValue'] ?? ''));
    }
}
