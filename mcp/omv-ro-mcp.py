#!/usr/bin/env python3
"""
OpenMediaVault Read-Only MCP Server (omv-ro-mcp)
================================================
Companion Model Context Protocol (MCP) server for `openmediavault-ro-api`.
Exposes 8 strictly read-only tools for AI coding assistants and infrastructure
auditors without requiring OMV administrator credentials or SSH access.

Configuration (Environment Variables):
  - OMV_HOST          : Base URL or IP of the OpenMediaVault server (e.g., "http://192.168.1.50")
  - OMV_RO_API_TOKEN  : 64-character hex Read-Only API token configured in OMV
                        (or synced via Infisical Universal Auth)
  - OMV_VERIFY_SSL    : Set to "true" to enforce TLS certificate verification (default: "false" for LAN IPs)

Optional Zero-Knowledge Infisical CLI Runtime Injection:
  If `OMV_RO_API_TOKEN` is not set in the environment and `INFISICAL_PROJECT_ID`
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
from typing import Any, Dict

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
    },
    {
        "name": "omv_get_disks_and_smart",
        "section": "disks",
        "description": (
            "Read physical block devices (`DiskMgmt.enumerateDevices`) and S.M.A.R.T. health/temperature "
            "assessments (`Smart.getList`), plus `/config/storage/hdparm` and `/config/storage/smart`."
        ),
    },
    {
        "name": "omv_get_storage_and_filesystems",
        "section": "storage",
        "description": (
            "Read all mounted and configured filesystems (`FileSystemMgmt.getList`), fstab mount points "
            "(`/config/system/fstab`), and Linux MD RAID arrays (`RaidMgmt.getList`)."
        ),
    },
    {
        "name": "omv_get_shares_and_exports",
        "section": "shares",
        "description": (
            "Read all OpenMediaVault shared folders (`ShareMgmt.getList`), SMB/CIFS shares, "
            "NFS exports, and rsync module configurations (with passwords automatically redacted)."
        ),
    },
    {
        "name": "omv_get_ups_and_power",
        "section": "ups",
        "description": (
            "Read OpenMediaVault NUT / UPS configuration (`/config/services/nut`), live `upsc` telemetry, "
            "scheduled power-management jobs, and cron jobs."
        ),
    },
    {
        "name": "omv_get_network_and_services",
        "section": "network",
        "description": (
            "Read OpenMediaVault network interfaces (`Network.enumerateConfiguredDevices`), general "
            "network settings, firewall rules, SSH daemon settings, and high-level service status (`Services.getStatus`)."
        ),
    },
    {
        "name": "omv_get_apt_and_plugins",
        "section": "apt",
        "description": (
            "Read installed and available OpenMediaVault plugins (`Plugin.enumeratePlugins`) and "
            "pending APT package upgrades (`Apt.enumerateUpgraded`)."
        ),
    },
    {
        "name": "omv_get_redacted_config_xml",
        "section": "config_xml",
        "description": (
            "Read the complete OpenMediaVault `/etc/openmediavault/config.xml` configuration tree "
            "parsed as JSON with all passwords, tokens, private keys, and secrets redacted server-side."
        ),
    },
]

SECTION_BY_TOOL = {t["name"]: t["section"] for t in TOOLS}


def fetch_creds_via_infisical() -> Dict[str, str]:
    """
    Retrieve OMV_HOST and OMV_RO_API_TOKEN from environment variables or, if
    INFISICAL_PROJECT_ID is configured, via `infisical run` inside a child Python process.
    """
    host = os.environ.get("OMV_HOST", "").strip()
    token = os.environ.get("OMV_RO_API_TOKEN", "").strip()
    if host and token:
        return {"host": host, "token": token}

    project_id = os.environ.get("INFISICAL_PROJECT_ID", "").strip()
    if project_id:
        helper_code = (
            "import json, os, sys; "
            "sys.stdout.write(json.dumps({"
            "'host': os.environ.get('OMV_HOST', ''), "
            "'token': os.environ.get('OMV_RO_API_TOKEN', '')"
            "}))"
        )
        cmd = [
            "infisical",
            "run",
            f"--projectId={project_id}",
            f"--env={DEFAULT_INFISICAL_ENV}",
            f"--path={DEFAULT_INFISICAL_PATH}",
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
        except Exception:
            pass

    return {"host": host, "token": token}


def query_omv_ro_api(section: str) -> Dict[str, Any]:
    creds = fetch_creds_via_infisical()
    host = creds.get("host", "")
    token = creds.get("token", "")
    if not host:
        return {
            "error": (
                "OMV_HOST is not configured. Set OMV_HOST (e.g. 'http://192.168.1.50') "
                "in your MCP environment or in Infisical."
            )
        }
    if not token:
        return {
            "error": (
                "OMV_RO_API_TOKEN is not configured. Set OMV_RO_API_TOKEN in your MCP environment "
                "or configure INFISICAL_PROJECT_ID for Infisical runtime injection."
            )
        }

    if not host.startswith(("http://", "https://")):
        base_url = f"http://{host}"
    else:
        base_url = host.rstrip("/")

    rpc_url = f"{base_url}/rpc.php"
    payload = json.dumps(
        {
            "service": "RoApiProxy",
            "method": "query",
            "params": {
                "section": section,
                "token": token,
            },
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
            "User-Agent": "omv-ro-mcp/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as resp:
            raw = resp.read().decode("utf-8")
            parsed = json.loads(raw)
            if parsed.get("error"):
                return {"error": parsed["error"], "endpoint": rpc_url}
            return parsed.get("response", parsed)
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        return {
            "error": f"HTTP {exc.code} from {rpc_url}",
            "details": body[:1000],
        }
    except Exception as exc:
        return {
            "error": f"Failed to reach OpenMediaVault Read-Only API at {rpc_url}: {exc}",
            "hint": (
                "Verify `openmediavault-ro-api` is installed and enabled under "
                "`Services -> Read-Only API` in the OMV Web UI."
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
                    "properties": {},
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

        result = query_omv_ro_api(section)
        is_error = "error" in result and len(result) <= 3
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
