#!/usr/bin/env python3
"""
OpenMediaVault Read-Only MCP Server (omv-ro-mcp)
================================================
Companion Model Context Protocol (MCP) server for `openmediavault-ro-api`.
Exposes 12 strictly read-only tools (including `omv_get_diagnostics` and
`omv_get_logs` for agentic self-diagnosis and feedback) without requiring
OMV administrator credentials or SSH access.

Configuration (Environment Variables — No Infisical Required):
  - OMV_HOST               : Base URL or IP of the OpenMediaVault server (e.g., "http://192.168.1.50")
  - OMV_RO_API_TOKEN       : 64-character hex Read-Only API token configured in OMV
  - OMV_RO_API_TOKEN_FILE  : Optional path to a chmod 0600 file containing the token (alternative
                             to putting OMV_RO_API_TOKEN directly in mcp_config.json)
  - OMV_VERIFY_SSL         : Set to "true" to enforce TLS certificate verification (default: "false" for LAN IPs)

Optional Zero-Knowledge Infisical CLI Runtime Injection:
  If `OMV_RO_API_TOKEN` / `OMV_RO_API_TOKEN_FILE` are not set and `INFISICAL_PROJECT_ID`
  is provided, `omv-ro-mcp` automatically invokes `infisical run` in a child
  process so secrets never appear in your MCP client config file.
    - INFISICAL_PROJECT_ID : Infisical Project ID
    - INFISICAL_ENV        : Infisical Environment slug (default: "prod")
    - INFISICAL_PATH       : Infisical secret folder path (default: "/omv")
"""

import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

DEFAULT_INFISICAL_ENV = os.environ.get("INFISICAL_ENV", "prod")
DEFAULT_INFISICAL_PATH = os.environ.get("INFISICAL_PATH", "/omv")

TOOLS = [
    {
        "name": "omv_get_overview",
        "section": "overview",
        "description": (
            "Read OpenMediaVault system overview, version, hostname, uptime, CPU/memory utilization, "
            "and pending configuration dirty-state (`isDirty`)."
        ),
        "properties": {},
    },
    {
        "name": "omv_get_disks_and_smart",
        "section": "disks",
        "description": (
            "Read physical block devices (`DiskMgmt.enumerateDevices`) and S.M.A.R.T. health/temperature "
            "assessments (`Smart.getList`), plus per-drive S.M.A.R.T. attributes and self-test logs."
        ),
        "properties": {
            "devicefile": {
                "type": "string",
                "description": "Optional specific device path (e.g. '/dev/sda' or '/dev/nvme0n1').",
            }
        },
    },
    {
        "name": "omv_get_storage_and_filesystems",
        "section": "storage",
        "description": (
            "Read all mounted and configured filesystems (`FileSystemMgmt.enumerateFilesystems`), "
            "fstab mount points (`FsTab.enumerateEntries`), `/proc/mdstat`, and ZFS pool status."
        ),
        "properties": {},
    },
    {
        "name": "omv_get_shares_and_exports",
        "section": "shares",
        "description": (
            "Read all OpenMediaVault shared folders (`ShareMgmt.enumerateSharedFolders`), filesystem snapshots, "
            "SMB/CIFS shares, and NFS exports (with passwords automatically redacted)."
        ),
        "properties": {},
    },
    {
        "name": "omv_get_ups_and_power",
        "section": "ups",
        "description": (
            "Read OpenMediaVault NUT / UPS configuration (`Nut.get`), live `upsc` telemetry (`Nut.getStats`), "
            "redacted `/etc/nut/*.conf` files, scheduled power-management jobs, and cron jobs."
        ),
        "properties": {},
    },
    {
        "name": "omv_get_network_and_services",
        "section": "network",
        "description": (
            "Read OpenMediaVault network interfaces (`Network.enumerateDevicesList`), general "
            "network settings, proxy settings, TLS/SSH certificate metadata, and service status (`Services.getStatus`)."
        ),
        "properties": {},
    },
    {
        "name": "omv_get_apt_and_plugins",
        "section": "apt",
        "description": (
            "Read installed OpenMediaVault plugins (`Plugin.enumeratePlugins`), APT repository settings, "
            "and pending APT package upgrades (`Apt.enumerateUpgraded`)."
        ),
        "properties": {},
    },
    {
        "name": "omv_get_omv_extras",
        "section": "omv_extras",
        "description": (
            "Auto-detect and audit installed OMV-Extras and community/official plugins: live runtime status "
            "and settings for Compose/Docker, MergerFS, SnapRAID, ZFS, KVM/Libvirt, WireGuard, BorgBackup, "
            "RemoteMount, LUKS, MD RAID, iSCSI/TGT, CpuTemp, Autoshutdown, Flashmemory, Rsnapshot, UsbBackup, "
            "Symlinks, ResetPerms, Scripts, ClamAV, Bcache, FTP/SFTP, and redacted /config/services/* XML nodes."
        ),
        "properties": {},
    },
    {
        "name": "omv_inspect_rpc",
        "section": "rpc_inspect",
        "description": (
            "Discover all registered RPC services in omv-engined (including any newly installed OMV-Extras "
            "or third-party plugin) or call any strictly read-only RPC method (get*, enumerate*, list*, is*, "
            "has*, status*) with automatic pagination and server-side secret redaction."
        ),
        "properties": {
            "rpc_service": {
                "type": "string",
                "description": (
                    "Optional OMV RPC service name (e.g. 'Compose', 'Zfs', 'Mergerfs', 'SnapRaid', 'Kvm', "
                    "'Wireguard', 'BorgBackup', 'Nut', 'Smart'). Leave empty or set to 'discover' to list all "
                    "registered RPC services and their allowed read-only methods."
                ),
            },
            "rpc_method": {
                "type": "string",
                "description": (
                    "Optional read-only method name on `rpc_service` (e.g. 'getContainerList', 'getSettings', "
                    "'getList'). Mutating/exec methods are strictly blocked by the server."
                ),
            },
            "rpc_params": {
                "type": "string",
                "description": (
                    "Optional JSON object string of parameters for `rpc_method` "
                    "(e.g. '{\"start\":0,\"limit\":50}'). Automatically defaults to full pagination "
                    "for *List methods when omitted."
                ),
            },
        },
    },
    {
        "name": "omv_get_redacted_config_xml",
        "section": "config_xml",
        "description": (
            "Read the complete OpenMediaVault `/etc/openmediavault/config.xml` configuration tree "
            "parsed as JSON with all passwords, tokens, private keys, and secrets redacted server-side."
        ),
        "properties": {},
    },
    {
        "name": "omv_get_logs",
        "section": "logs",
        "description": (
            "Read redacted OpenMediaVault system, daemon, S.M.A.R.T., NUT/UPS, SMB, NFS, NGINX, "
            "omv-engined, or Read-Only API plugin logs for agentic troubleshooting."
        ),
        "properties": {
            "logfile": {
                "type": "string",
                "description": (
                    "Log source to query: 'roapi' (default, Read-Only API audit/error log), "
                    "'syslog', 'daemon', 'messages', 'auth', 'smartd', 'smb', 'rsync', "
                    "'nut' (nut-server/nut-monitor/nut-driver journal), 'engined' (openmediavault-engined journal), "
                    "'nginx', or 'nfs'."
                ),
                "default": "roapi",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of recent log entries to return (1-500, default 100).",
                "minimum": 1,
                "maximum": 500,
                "default": 100,
            },
        },
    },
    {
        "name": "omv_get_diagnostics",
        "section": "diagnostics",
        "description": (
            "Agent self-diagnostic & feedback tool: returns plugin version/configuration state, "
            "enabled vs. disabled read-only scopes, Infisical Universal Auth sync status & cache health, "
            "live latency/health probes across OMV sub-RPC services, and recent Read-Only API log entries."
        ),
        "properties": {
            "limit": {
                "type": "integer",
                "description": "Number of recent Read-Only API log entries to include (1-500, default 100).",
                "minimum": 1,
                "maximum": 500,
                "default": 100,
            }
        },
    },
]

SECTION_BY_TOOL = {t["name"]: t["section"] for t in TOOLS}


def fetch_creds_via_infisical() -> Dict[str, Any]:
    """
    Retrieve OMV_HOST and OMV_RO_API_TOKEN from:
      1. Environment variables (OMV_HOST + OMV_RO_API_TOKEN)
      2. Token file (OMV_HOST + OMV_RO_API_TOKEN_FILE, e.g. ~/.config/omv-ro/token)
      3. Optional Infisical CLI runtime injection (if INFISICAL_PROJECT_ID is set)
    """
    env_file = os.path.expanduser("~/.config/environment.d/90-infisical.conf")
    if os.path.isfile(env_file):
        try:
            with open(env_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
        except Exception:
            pass

    host = os.environ.get("OMV_HOST", "").strip()
    token = os.environ.get("OMV_RO_API_TOKEN", "").strip()
    token_file = os.environ.get("OMV_RO_API_TOKEN_FILE", "").strip()

    if not token and token_file:
        expanded = os.path.expandvars(os.path.expanduser(token_file))
        if os.path.isfile(expanded):
            try:
                with open(expanded, "r", encoding="utf-8") as fh:
                    token = fh.read().strip()
            except Exception as exc:
                return {
                    "host": host,
                    "token": "",
                    "source": f"token_file ({expanded})",
                    "infisical_error": f"Failed to read OMV_RO_API_TOKEN_FILE: {exc}",
                }

    if host and token:
        return {
            "host": host,
            "token": token,
            "source": "token_file" if token_file else "environment",
        }

    project_id = os.environ.get("INFISICAL_PROJECT_ID", "").strip()
    infisical_err: Optional[str] = None
    if project_id:
        helper_code = (
            "import json, os, sys; "
            "sys.stdout.write(json.dumps({"
            "'host': os.environ.get('OMV_HOST', ''), "
            "'token': os.environ.get('OMV_RO_API_TOKEN', '')"
            "}))"
        )
        for candidate_path in (DEFAULT_INFISICAL_PATH, "/"):
            cmd = [
                "infisical",
                "run",
                f"--projectId={project_id}",
                f"--env={DEFAULT_INFISICAL_ENV}",
                f"--path={candidate_path}",
                "--silent",
                "--",
                sys.executable,
                "-c",
                helper_code,
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
                if proc.returncode == 0 and proc.stdout.strip():
                    data = json.loads(proc.stdout.strip())
                    if data.get("token"):
                        token = data["token"].strip()
                    if data.get("host"):
                        host = data["host"].strip()
                    if token and host:
                        infisical_err = None
                        break
                else:
                    infisical_err = (proc.stderr or proc.stdout or f"exit code {proc.returncode}").strip()[:400]
            except Exception as exc:
                infisical_err = str(exc)

    return {
        "host": host,
        "token": token,
        "source": "infisical" if project_id else "environment",
        "infisical_error": infisical_err,
    }


def query_omv_ro_api(section: str, extra_params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    creds = fetch_creds_via_infisical()
    host = creds.get("host", "")
    token = creds.get("token", "")
    if not host or not token:
        return {
            "error": "Missing OpenMediaVault Read-Only API credentials (OMV_HOST or OMV_RO_API_TOKEN).",
            "_agent_troubleshooting_feedback": {
                "failure_layer": "mcp_credentials",
                "omv_host_present": bool(host),
                "omv_ro_api_token_present": bool(token),
                "credential_source": creds.get("source"),
                "infisical_cli_error": creds.get("infisical_error"),
                "remediation": (
                    "Ensure OMV_HOST and OMV_RO_API_TOKEN are set in the environment or stored in Infisical "
                    f"(env='{DEFAULT_INFISICAL_ENV}', path='{DEFAULT_INFISICAL_PATH}') and that `Save Changes` "
                    "was clicked in the Infisical UI."
                ),
            },
        }

    if not host.startswith(("http://", "https://")):
        base_url = f"http://{host}"
    else:
        base_url = host.rstrip("/")

    rpc_url = f"{base_url}/ro-api.php"
    rpc_params: Dict[str, Any] = {
        "section": section,
        "token": token,
    }
    if extra_params:
        for k in ("devicefile", "logfile", "limit", "rpc_service", "rpc_method", "rpc_params"):
            if k in extra_params and extra_params[k] is not None:
                if k == "rpc_params" and isinstance(extra_params[k], dict):
                    rpc_params[k] = json.dumps(extra_params[k])
                else:
                    rpc_params[k] = extra_params[k]

    payload = json.dumps(
        {
            "service": "RoApi",
            "method": "query",
            "params": rpc_params,
            "options": None,
        }
    ).encode("utf-8")

    verify_ssl = os.environ.get("OMV_VERIFY_SSL", "false").lower() in ("1", "true", "yes")
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "X-OMV-RO-Token": token,
            "User-Agent": "omv-ro-mcp/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as resp:
            raw = resp.read().decode("utf-8")
            parsed = json.loads(raw)
            if parsed.get("error"):
                err_obj = parsed["error"]
                msg = err_obj.get("message", "") if isinstance(err_obj, dict) else str(err_obj)
                code = err_obj.get("code") if isinstance(err_obj, dict) else None
                return {
                    "error": err_obj,
                    "endpoint": rpc_url,
                    "_agent_troubleshooting_feedback": classify_omv_error(code, msg, section),
                }
            return parsed.get("response", parsed)
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        msg = body[:1000]
        try:
            parsed_err = json.loads(body)
            if isinstance(parsed_err, dict) and parsed_err.get("error"):
                e = parsed_err["error"]
                msg = e.get("message", msg) if isinstance(e, dict) else str(e)
        except Exception:
            pass
        return {
            "error": f"HTTP {exc.code} from {rpc_url}",
            "details": msg,
            "_agent_troubleshooting_feedback": classify_omv_error(exc.code, msg, section),
        }
    except Exception as exc:
        return {
            "error": f"Failed to reach OpenMediaVault Read-Only API at {rpc_url}: {exc}",
            "_agent_troubleshooting_feedback": {
                "failure_layer": "network_connectivity",
                "endpoint": rpc_url,
                "exception": str(exc),
                "remediation": (
                    "Verify the OpenMediaVault host is reachable on the network, NGINX is running, "
                    "and if executing inside a network-isolated sandbox, re-run with sandbox network access enabled."
                ),
            },
        }


def classify_omv_error(code: Any, message: str, section: str) -> Dict[str, Any]:
    msg_lower = (message or "").lower()
    if (
        code == 404
        or "rpc service 'roapi' not found" in msg_lower
        or "service 'roapi' not found" in msg_lower
        or "session not authenticated" in msg_lower
    ):
        return {
            "failure_layer": "plugin_not_installed",
            "http_or_rpc_code": code,
            "remediation": (
                "The `openmediavault-ro-api` plugin (`/ro-api.php`) is not installed on this OpenMediaVault host yet. "
                "Add the plugin APT repository via `openmediavault-apt` (`System -> Update Management -> Settings -> Other Software`) and install "
                "`openmediavault-ro-api` in `System -> Plugins`, or install `openmediavault-ro-api_1.0.0-1_all.deb` via APT."
            ),
        }
    if code == 401 or "invalid read-only api token" in msg_lower:
        return {
            "failure_layer": "token_authentication",
            "http_or_rpc_code": code,
            "remediation": (
                "The provided OMV_RO_API_TOKEN was rejected by OpenMediaVault. Check `Services -> Read-Only API` "
                "in the OMV Web UI (or Infisical sync settings) and check `Diagnostics -> System Logs -> Logs -> Read-Only API`."
            ),
        }
    if "client ip" in msg_lower and "not permitted" in msg_lower:
        return {
            "failure_layer": "ip_allowlist",
            "http_or_rpc_code": code,
            "remediation": (
                "Your client IP is not in the `Allowed client IPs / subnets` list in `Services -> Read-Only API`. "
                "Add your IP/subnet in the OMV Web UI."
            ),
        }
    if "scope" in msg_lower and "disabled" in msg_lower:
        return {
            "failure_layer": "scope_disabled",
            "requested_section": section,
            "http_or_rpc_code": code,
            "remediation": (
                f"The '{section}' scope is currently unchecked in `Services -> Read-Only API` in the OMV Web UI. "
                "Call `omv_get_diagnostics` to inspect `scope_permissions.enabled_scopes`."
            ),
        }
    if "read-only api is disabled" in msg_lower:
        return {
            "failure_layer": "service_disabled",
            "http_or_rpc_code": code,
            "remediation": "Enable the plugin checkbox under `Services -> Read-Only API` in the OMV Web UI.",
        }
    return {
        "failure_layer": "omv_rpc_error",
        "requested_section": section,
        "http_or_rpc_code": code,
        "remediation": (
            "Call `omv_get_diagnostics` and `omv_get_logs(logfile='roapi')` or `omv_get_logs(logfile='engined')` "
            "to inspect detailed backend error logs."
        ),
    }


def send_jsonrpc(msg: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def handle_request(req: Dict[str, Any]) -> None:
    method = req.get("method")
    msg_id = req.get("id")

    if method == "notifications/initialized":
        return

    if method == "initialize":
        send_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "omv-ro",
                        "version": "1.0.0",
                    },
                },
            }
        )
        return

    if method == "tools/list":
        tool_defs = [
            {
                "name": t["name"],
                "description": t["description"],
                "inputSchema": {
                    "type": "object",
                    "properties": t.get("properties", {}),
                    "additionalProperties": False,
                },
            }
            for t in TOOLS
        ]
        send_jsonrpc({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": tool_defs}})
        return

    if method == "tools/call":
        params = req.get("params", {})
        tool_name = params.get("name", "")
        tool_args = params.get("arguments") or {}
        section = SECTION_BY_TOOL.get(tool_name)
        if not section:
            send_jsonrpc(
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
                }
            )
            return

        result = query_omv_ro_api(section, tool_args if isinstance(tool_args, dict) else None)
        is_error = "error" in result and "_agent_feedback" not in result
        send_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, indent=2, sort_keys=True),
                        }
                    ],
                    "isError": is_error,
                },
            }
        )
        return

    if msg_id is not None:
        send_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
        )


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] in ("--test", "-t"):
        section = sys.argv[2] if len(sys.argv) > 2 else "overview"
        extra = json.loads(sys.argv[3]) if len(sys.argv) > 3 else None
        res = query_omv_ro_api(section, extra)
        print(json.dumps(res, indent=2, sort_keys=True))
        sys.exit(1 if ("error" in res and "_agent_feedback" not in res) else 0)

    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            handle_request(req)
        except Exception as exc:
            send_jsonrpc(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {exc}"},
                }
            )


if __name__ == "__main__":
    main()
