# `openmediavault-ro-api` — Read-Only JSON-RPC API & Infisical Auditor Plugin for OpenMediaVault 7 / 8

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![OpenMediaVault](https://img.shields.io/badge/OpenMediaVault-7.x%20%7C%208.x-5aa3e8)](https://www.openmediavault.org/)

A native OpenMediaVault `.deb` plugin (and companion **Model Context Protocol (MCP)** server) that exposes a strictly **read-only, token-authenticated, subnet-restricted JSON-RPC endpoint** (`RoApiProxy::query`) for infrastructure auditing, AI coding assistants, and monitoring tools—**without** sharing OMV `admin` credentials, browser session cookies, or SSH root access.

---

## Why Does This Plugin Exist?

OpenMediaVault's built-in JSON-RPC interface (`/rpc.php`) requires an authenticated `admin` Web UI session, and every administrator session carries full read/write privileges (`OMV_ROLE_ADMINISTRATOR`). Neither upstream `openmediavault` nor `omv-extras` provides a read-only API token or scoped auditor role.

`openmediavault-ro-api` solves this cleanly inside OMV's native plugin architecture:

1. **Zero Write Methods:** Exposes a single external JSON-RPC proxy method (`RoApiProxy::query`) over OMV's existing NGINX web server (`/rpc.php`). No `set`, `delete`, `applyChanges`, or shell-execution RPCs exist on the token-authenticated endpoint.
2. **100% Configurable via the OMV Workbench UI (`Services` -> `Read-Only API`):** Every feature—from per-section scope toggles and custom redaction keys to anti-bruteforce delays, syslog audit logging, one-click token regeneration, and Infisical Universal Auth token sync—is controlled directly from the OpenMediaVault Web UI.
3. **Server-Side Recursive Secret Redaction:** Before any response leaves `omv-engined`, a recursive redactor strips all fields matching sensitive key names (`password`, `passwd`, `secret`, `token`, `apikey`, `privatekey`, `psk`, `passphrase`, `chap`, `credentials`, `infisicalclientsecret`, plus any custom comma-separated patterns configured in the UI).
4. **Non-Destructive Uninstall Guarantee:** Uninstalling or purging the `.deb` package (`apt remove` or `apt purge`) **never** runs `omv_config_delete` against `/etc/openmediavault/config.xml`. Your configuration under `/config/services/roapi` remains intact across upgrades or reinstalls.
5. **Optional Infisical Universal Auth Sync:** Instead of managing static tokens manually, OMV can pull and cache (`0600 /run/openmediavault-ro-api.cache`) the expected API token directly from an [Infisical](https://infisical.com) vault using a read-only Machine Identity.

---

## Installation

### Method 1: OpenMediaVault Web UI (No SSH Required)

1. Download `openmediavault-ro-api_1.0.0-1_all.deb` from the [GitHub Releases](https://github.com/shurushetr/openmediavault-ro-api/releases) page (or build it from source with `./build-deb.sh`).
2. Open your OpenMediaVault Web UI and navigate to **`System` -> `Plugins`**.
3. Click the **`Upload`** button (top toolbar) and select `openmediavault-ro-api_1.0.0-1_all.deb`.
4. Locate **`openmediavault-ro-api`** in the plugin list, select it, and click **`Install`**.
5. Click the yellow banner at the top of the UI to **Apply pending configuration changes**.

### Method 2: Command Line (`dpkg` / `apt`)

```bash
sudo apt-get install -f ./openmediavault-ro-api_1.0.0-1_all.deb
```

---

## Workbench UI Configuration (`Services` -> `Read-Only API`)

All 24 configuration options are exposed in the OpenMediaVault Workbench UI under **`Services` -> `Read-Only API`**, organized into three logical dividers:

### 1. General & Access Control
| UI Field | XML Key | Default | Description |
| :--- | :--- | :--- | :--- |
| **Enabled** | `enable` | `true` | Master switch for the Read-Only JSON-RPC endpoint (`RoApiProxy::query`). |
| **Static Read-Only API Token** | `apitoken` | Auto-generated 256-bit hex | Bearer token required when Infisical Universal Auth is disabled (or used as fallback). |
| **Generate new random 256-bit API token on Save** | `regeneratetoken` | `false` | One-click checkbox that generates a fresh 64-character CSPRNG hex token upon saving and resets itself to `false`. |
| **Allowed Client IPs / Subnets** | `allowedips` | `127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16` | Comma-separated list of IPv4 addresses or CIDR blocks allowed to query the API. Leave empty to allow any source IP with a valid token. |
| **Invalid Token Delay (ms)** | `faildelayms` | `250` (`0`–`5000`) | Artificial delay in milliseconds added when a request fails IP or token validation to throttle brute-force attempts. |
| **Syslog Audit Logging** | `auditlog` | `failures` | Controls syslog auditing (`omv-ro-api`): `none`, `failures` (denied IPs/tokens only), or `all` (both denied and successful queries). |
| **Comment** | `comment` | `Read-Only API & Infisical Auditor` | Optional notes or audit description. |

### 2. Allowed Read-Only Data Scopes & Redaction
Granularly enable or disable individual query sections from the UI:

| UI Checkbox | XML Key | Default | Underlying OMV RPCs & XPaths |
| :--- | :--- | :--- | :--- |
| **Allow `overview` section** | `allow_overview` | `true` | `System::getInformation`, `/config/system/time`, `/config/system/powermanagement` |
| **Allow `disks` section** | `allow_disks` | `true` | `DiskMgmt::enumerateDevices`, `Smart::getList`, `/config/storage/hdparm`, `/config/storage/smart` |
| **Allow `storage` section** | `allow_storage` | `true` | `FileSystemMgmt::getList`, `RaidMgmt::getList`, `/config/system/fstab` |
| **Allow `shares` section** | `allow_shares` | `true` | `ShareMgmt::getList`, `Smb::getShareList`, `Nfs::getShareList`, `/config/services/smb`, `/config/services/nfs`, `/config/services/rsync` |
| **Allow `ups` section** | `allow_ups` | `true` | `/config/services/nut`, `Nut::getStats` (live `upsc` output), `PowerMgmt::getScheduleList`, `Cron::getList` |
| **Allow `network` section** | `allow_network` | `true` | `Network::enumerateConfiguredDevices`, `Services::getStatus`, `/config/system/network`, `/config/services/ssh` |
| **Allow `apt` section** | `allow_apt` | `true` | `Plugin::enumeratePlugins`, `Apt::enumerateUpgraded` |
| **Allow `config_xml` section** | `allow_configxml` | `true` | Full `/etc/openmediavault/config.xml` tree parsed as JSON with server-side recursive secret redaction |
| **Allow `logs` section** | `allow_logs` | `true` | Redacted system, daemon, S.M.A.R.T., NUT/UPS, SMB, NFS, NGINX, `omv-engined`, and `Read-Only API` logs (`LogFile::getList` + `journalctl`) |
| **Allow `diagnostics` section** | `allow_diagnostics` | `true` | Agent self-diagnostics: plugin version/config state, enabled scope matrix, Infisical sync health & cache status, sub-RPC latency probes, and recent audit events |
| **Additional Redacted Key Patterns** | `redactpatterns` | *(empty)* | Optional comma-separated list of custom key substrings to redact as `***REDACTED***` in addition to built-in patterns. |

### 3. Infisical Universal Auth Token Sync (Optional)
| UI Field | XML Key | Default | Description |
| :--- | :--- | :--- | :--- |
| **Use Infisical Universal Auth** | `infisicalenable` | `false` | Fetch the expected API token dynamically from an Infisical vault instead of relying solely on the local token. |
| **Infisical Base URL** | `infisicalurl` | `https://app.infisical.com` | Base URL of your Infisical Cloud or self-hosted instance. |
| **Infisical Project ID** | `infisicalprojectid` | *(empty)* | UUID of the Infisical Project containing the token secret. |
| **Infisical Environment Slug** | `infisicalenv` | `prod` | Environment slug (`prod`, `dev`, `staging`). |
| **Infisical Secret Path** | `infisicalpath` | `/omv` | Folder path inside the Infisical project. |
| **Infisical Secret Key Name** | `infisicalsecretkey` | `OMV_RO_API_TOKEN` | Name of the secret key in Infisical holding the expected Read-Only API token. |
| **Machine Identity Client ID** | `infisicalclientid` | *(empty)* | Universal Auth Client ID with read access to the secret path. |
| **Machine Identity Client Secret** | `infisicalclientsecret` | *(empty)* | Universal Auth Client Secret (masked in UI and automatically redacted from all API output). |
| **Infisical Token Cache TTL (seconds)** | `infisicalcachettl` | `300` (`30`–`86400`) | How long OMV caches the fetched secret in `/run/openmediavault-ro-api.cache` (`0600`) before refreshing. |
| **Verify Infisical TLS Certificate** | `infisicalverifyssl` | `true` | Disable only if your self-hosted Infisical instance uses a private CA not installed in Debian's system trust store. |
| **Allow Static Token Fallback if Infisical is Unreachable** | `infisicalfallback` | `true` | If enabled, OMV falls back to the local Static Read-Only API Token if the Infisical server is temporarily offline. |

---

## Querying the Read-Only JSON-RPC Endpoint (`curl` Example)

Once installed and enabled, you can query any allowed section with a standard HTTP `POST` to `/rpc.php`:

```bash
curl -sS -X POST "http://<OMV_HOST>/rpc.php" \
  -H "Content-Type: application/json" \
  -d '{
    "service": "RoApiProxy",
    "method": "query",
    "params": {
      "section": "overview",
      "token": "<YOUR_64_HEX_TOKEN>"
    },
    "options": null
  }' | jq .
```

Valid `section` values:
- `overview`
- `disks`
- `storage`
- `shares`
- `ups`
- `network`
- `apt`
- `config_xml`
- `logs` (accepts optional `"logfile": "roapi|syslog|daemon|messages|auth|smartd|smb|rsync|nut|engined|nginx|nfs"` and `"limit": 100`)
- `diagnostics` (agent self-diagnostics, scope matrix, Infisical sync health, sub-RPC latency probes, and recent audit log entries)
- `all` (returns all sections that are currently enabled in the UI)

Every response also includes an `_agent_feedback` block reporting execution duration (`duration_ms`), any partial sub-RPC errors (`partial_errors`), currently enabled/disabled scopes, and actionable troubleshooting hints.

---

## Native OMV Log Viewer (`Diagnostics` -> `System Logs` -> `Logs` -> `Read-Only API`)

The plugin registers `/var/log/openmediavault-ro-api.log` with OpenMediaVault's `LogFileSpec` engine so administrators can view, sort, and search all Read-Only API events (authorized queries, unauthorized IP/token attempts, disabled scope rejections, sub-RPC warnings, and Infisical sync status) directly in the OMV Web UI under **`Diagnostics` -> `System Logs` -> `Logs` -> `Read-Only API`**.

---

## Companion Model Context Protocol (`MCP`) Server

The repository includes a zero-dependency Python 3 MCP server ([`mcp/omv-ro-mcp.py`](mcp/omv-ro-mcp.py)) that exposes 10 read-only tools to MCP-compatible AI assistants (Claude Desktop, Cursor, Google Antigravity, Windsurf, etc.):

- `omv_get_overview`
- `omv_get_disks_and_smart`
- `omv_get_storage_and_filesystems`
- `omv_get_shares_and_exports`
- `omv_get_ups_and_power`
- `omv_get_network_and_services`
- `omv_get_apt_and_plugins`
- `omv_get_redacted_config_xml`
- `omv_get_logs` *(query `roapi`, `syslog`, `daemon`, `smartd`, `nut`, `engined`, `smb`, `nfs`, `nginx` logs)*
- `omv_get_diagnostics` *(agent self-diagnostic & feedback loop tool)*

### Option A: Standard Environment Variables (`mcp_config.json`)

```json
{
  "mcpServers": {
    "omv-ro": {
      "command": "python3",
      "args": ["/path/to/openmediavault-ro-api/mcp/omv-ro-mcp.py"],
      "env": {
        "OMV_HOST": "http://192.168.1.50",
        "OMV_RO_API_TOKEN": "your-64-char-hex-token"
      }
    }
  }
}
```

### Option B: Zero-Knowledge Infisical CLI Runtime Injection

If you store `OMV_HOST` and `OMV_RO_API_TOKEN` inside Infisical, pass only `INFISICAL_PROJECT_ID` in `mcp_config.json`—no secrets are written to disk:

```json
{
  "mcpServers": {
    "omv-ro": {
      "command": "python3",
      "args": ["/path/to/openmediavault-ro-api/mcp/omv-ro-mcp.py"],
      "env": {
        "INFISICAL_PROJECT_ID": "your-infisical-project-uuid",
        "INFISICAL_ENV": "prod",
        "INFISICAL_PATH": "/omv"
      }
    }
  }
}
```

---

## Building from Source

### Fast Standalone Build (`dpkg-deb`)
Requires only `dpkg-dev`, `gzip`, and `bash`:

```bash
./build-deb.sh
# Output: dist/openmediavault-ro-api_1.0.0-1_all.deb
```

To pre-seed an initial token into a private build without committing any token to Git:

```bash
DEFAULT_OMV_RO_TOKEN="$(openssl rand -hex 32)" ./build-deb.sh
```

### Standard Debian Package Build (`dpkg-buildpackage`)
Requires `debhelper`:

```bash
dpkg-buildpackage -us -uc -b
```

---

## License

Released under the [GNU General Public License v3.0 or later (GPL-3.0+)](LICENSE), matching upstream OpenMediaVault.
