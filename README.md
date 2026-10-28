# `openmediavault-ro-api` — Read-Only API & MCP Server for OpenMediaVault 7 / 8

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![OpenMediaVault](https://img.shields.io/badge/OpenMediaVault-7.x%20%7C%208.x-5aa3e8)](https://www.openmediavault.org/)
[![MCP Compatible](https://img.shields.io/badge/MCP-12%20Read--Only%20Tools-10a37f)](https://modelcontextprotocol.io/)

Give AI coding assistants (**Claude Desktop, Claude Code, Cursor, Google Antigravity, VS Code Copilot, Windsurf, Cline**), dashboards, and infrastructure auditors **safe, strictly read-only visibility** into your OpenMediaVault NAS—**without** giving them your `admin` password, SSH root access, or permission to modify anything.

---

## Why Use `openmediavault-ro-api`?

By default, OpenMediaVault's API (`/rpc.php`) requires an administrator login session (`OMV_ROLE_ADMINISTRATOR`), which grants full permission to format disks, delete shared folders, or change passwords.

`openmediavault-ro-api` installs as a native `.deb` plugin inside OpenMediaVault and adds a **dedicated, server-enforced Read-Only endpoint (`RoApiProxy::query`)**:

- **Strictly Read-Only by Design:** Exposes zero `set`, `delete`, `applyChanges`, or shell-execution methods. Even its dynamic plugin inspector (`omv_inspect_rpc`) enforces a server-side allowlist that permits only read-only getters (`get*`, `enumerate*`, `list*`, `is*`, `has*`, `status*`).
- **Automatic Password & Secret Redaction:** Every response is scrubbed inside `omv-engined` *before* it leaves your NAS. Passwords, private keys, API tokens, WireGuard keys, and NUT/SMB secrets are replaced with `***REDACTED***`.
- **Full `omv-extras` Support:** Audits both core OpenMediaVault services and `omv-extras` plugins (Docker Compose, MergerFS, SnapRAID, ZFS, KVM/Libvirt, WireGuard, BorgBackup, RemoteMount, LUKS, MD RAID, iSCSI, CPU Temp, and more).
- **Built for AI Agents:** Includes an inline `_agent_feedback` block on every response plus dedicated `omv_get_diagnostics` and `omv_get_logs` tools so AI agents can self-diagnose permission scopes, service latency, and daemon logs.
- **100% Configurable in the OMV Web UI:** Control allowed IP subnets, toggle individual data scopes on/off, rotate tokens with one click, and view audit logs directly inside the OpenMediaVault interface.
- **Safe Uninstall Guarantee:** Removing or purging the plugin **never** deletes your saved settings in `/etc/openmediavault/config.xml`.

<!-- SCREENSHOT 1 PLACEHOLDER -->
<!--
![OpenMediaVault Read-Only API Settings](docs/images/01-omv-ro-api-settings-overview.png)
-->

---

## Quick Start (3 Minutes — No SSH Required)

### Step 1: Install the Plugin in OpenMediaVault

1. Download **`openmediavault-ro-api_1.0.0-1_all.deb`** from the [**Releases**](https://github.com/shurushetr/openmediavault-ro-api/releases) page.
2. Open your OpenMediaVault Web UI and go to **`System` -> `Plugins`**.
3. Click the **`Upload`** button on the top toolbar and select `openmediavault-ro-api_1.0.0-1_all.deb`.
4. Find **`openmediavault-ro-api`** in the plugin list, select it, and click **`Install`**.
5. Click the yellow banner at the top of the screen to **Apply pending configuration changes**.

<!-- SCREENSHOT 2 PLACEHOLDER -->
<!--
![Uploading and Installing openmediavault-ro-api in System -> Plugins](docs/images/02-omv-plugin-upload-install.png)
-->

*(Prefer the command line? Run `sudo apt-get install -f ./openmediavault-ro-api_1.0.0-1_all.deb` over SSH.)*

---

### Step 2: Copy Your Auto-Generated Read-Only Token

1. In the OpenMediaVault Web UI, go to **`Services` -> `Read-Only API`**.
2. Ensure **`Enabled`** is checked.
3. Under **`Read-Only API token`**, click the **eye icon** to reveal your auto-generated 64-character token and copy it.
   - *Tip:* To generate a brand-new token at any time, check **"Generate new random 256-bit token on save"** and click **Save**.
4. Check **`Allowed client IPs / subnets`** (defaults to standard private LAN ranges: `127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16`).

<!-- SCREENSHOT 3 PLACEHOLDER -->
<!--
![Copying the Read-Only API Token and Scope Checkboxes](docs/images/03-omv-token-and-scopes.png)
-->

---

### Step 3: Connect Your AI Assistant (MCP Setup Guide)

Download [**`mcp/omv-ro-mcp.py`**](mcp/omv-ro-mcp.py) to your computer (requires only **Python 3.8+** standard library—no `pip install` needed!):

```bash
mkdir -p ~/.local/bin
curl -fsSL https://raw.githubusercontent.com/shurushetr/openmediavault-ro-api/main/mcp/omv-ro-mcp.py -o ~/.local/bin/omv-ro-mcp.py
chmod +x ~/.local/bin/omv-ro-mcp.py
```

Choose your AI client below and replace `http://192.168.1.50` with your OMV IP/URL and `YOUR_64_CHAR_TOKEN` with the token from Step 2:

<details open>
<summary><b>1. Claude Desktop (macOS / Windows / Linux)</b></summary>

Edit your Claude Desktop config file:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "omv-ro": {
      "command": "python3",
      "args": ["/Users/yourname/.local/bin/omv-ro-mcp.py"],
      "env": {
        "OMV_HOST": "http://192.168.1.50",
        "OMV_RO_API_TOKEN": "YOUR_64_CHAR_TOKEN"
      }
    }
  }
}
```
Restart Claude Desktop. You will see the 12 `omv_*` tools under the hammer/tools icon.
</details>

<details>
<summary><b>2. Claude Code CLI</b></summary>

Run the following command in your terminal:

```bash
claude mcp add omv-ro \
  -e OMV_HOST="http://192.168.1.50" \
  -e OMV_RO_API_TOKEN="YOUR_64_CHAR_TOKEN" \
  -- python3 ~/.local/bin/omv-ro-mcp.py
```
Verify with `claude mcp list`.
</details>

<details>
<summary><b>3. Cursor IDE</b></summary>

Open **Cursor Settings** -> **MCP** -> **Add new global MCP server** (or edit `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "omv-ro": {
      "command": "python3",
      "args": ["/home/yourname/.local/bin/omv-ro-mcp.py"],
      "env": {
        "OMV_HOST": "http://192.168.1.50",
        "OMV_RO_API_TOKEN": "YOUR_64_CHAR_TOKEN"
      }
    }
  }
}
```
</details>

<details>
<summary><b>4. Google Antigravity (AGY) & Gemini CLI</b></summary>

Add `omv-ro` to `~/.gemini/config/mcp_config.json` (Antigravity) or `~/.gemini/settings.json` (Gemini CLI):

```json
{
  "mcpServers": {
    "omv-ro": {
      "command": "python3",
      "args": ["/home/yourname/.local/bin/omv-ro-mcp.py"],
      "env": {
        "OMV_HOST": "http://192.168.1.50",
        "OMV_RO_API_TOKEN": "YOUR_64_CHAR_TOKEN"
      }
    }
  }
}
```
</details>

<details>
<summary><b>5. VS Code (GitHub Copilot Agent Mode / Cline / Roo Code)</b></summary>

For **VS Code Copilot Agent Mode**, add to `.vscode/mcp.json` (or your User `settings.json` under `"mcp": { "servers": { ... } }`):

```json
{
  "servers": {
    "omv-ro": {
      "type": "stdio",
      "command": "python3",
      "args": ["/home/yourname/.local/bin/omv-ro-mcp.py"],
      "env": {
        "OMV_HOST": "http://192.168.1.50",
        "OMV_RO_API_TOKEN": "YOUR_64_CHAR_TOKEN"
      }
    }
  }
}
```

For **Cline / Roo Code**, open **MCP Servers** -> **Configure MCP Servers** (`cline_mcp_settings.json`) and use the same `mcpServers` block as Claude Desktop.
</details>

<details>
<summary><b>6. Windsurf IDE</b></summary>

Edit `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "omv-ro": {
      "command": "python3",
      "args": ["/home/yourname/.local/bin/omv-ro-mcp.py"],
      "env": {
        "OMV_HOST": "http://192.168.1.50",
        "OMV_RO_API_TOKEN": "YOUR_64_CHAR_TOKEN"
      }
    }
  }
}
```
</details>

<details>
<summary><b>Security Tip: Keep Your Token Out of <code>mcp_config.json</code> (Using a Local Token File)</b></summary>

If you don't want your token stored in plaintext inside your IDE's MCP config file, save it in a `0600` file and use `OMV_RO_API_TOKEN_FILE`:

```bash
mkdir -p ~/.config/omv-ro
printf "%s" "YOUR_64_CHAR_TOKEN" > ~/.config/omv-ro/token
chmod 600 ~/.config/omv-ro/token
```

Then reference `OMV_RO_API_TOKEN_FILE` in your MCP config:

```json
"env": {
  "OMV_HOST": "http://192.168.1.50",
  "OMV_RO_API_TOKEN_FILE": "~/.config/omv-ro/token"
}
```
</details>

---

## Available MCP Tools (12 Read-Only Tools)

| MCP Tool | API Section | What It Audits |
| :--- | :--- | :--- |
| **`omv_get_overview`** | `overview` | Hostname, OMV/kernel version, CPU/RAM/load, uptime, NTP settings, pending config changes (`isDirty`), service states, WebGUI & SSH settings. |
| **`omv_get_disks_and_smart`** | `disks` | Physical block devices (`DiskMgmt`), temperatures, S.M.A.R.T. health assessments, attributes, and self-test logs (optional `devicefile` filter). |
| **`omv_get_storage_and_filesystems`** | `storage` | Filesystems, mount points (`/etc/fstab`), disk usage/capacity, Linux MD RAID (`/proc/mdstat`), and ZFS pool status (`zpool status`). |
| **`omv_get_shares_and_exports`** | `shares` | Shared folders, filesystem snapshots, SMB/CIFS shares, and NFS exports (with passwords redacted). |
| **`omv_get_ups_and_power`** | `ups` | NUT / UPS configuration, live `upsc` battery/load/runtime telemetry, redacted `/etc/nut/*.conf` files, standby/power schedules, and cron jobs. |
| **`omv_get_network_and_services`** | `network` | Network interfaces, DNS/gateway, proxy settings, TLS & SSH certificate metadata, and service status. |
| **`omv_get_apt_and_plugins`** | `apt` | Installed `openmediavault-*` plugins, APT repository settings, and pending package upgrades. |
| **`omv_get_omv_extras`** | `omv_extras` | Auto-detects and audits installed **`omv-extras`** & community plugins: **Compose/Docker** (containers, stats, compose files, volumes, networks, images), **MergerFS**, **SnapRAID**, **ZFS**, **KVM/Libvirt**, **WireGuard**, **BorgBackup**, **RemoteMount**, **LUKS**, **MD RAID**, **iSCSI/TGT**, **CpuTemp**, **Autoshutdown**, **Flashmemory**, **Rsnapshot**, **UsbBackup**, **Symlinks**, **ResetPerms**, **Scripts**, **ClamAV**, **Bcache**, **Podman**, **FTP/SFTP**, and **MiniDLNA**. |
| **`omv_inspect_rpc`** | `rpc_inspect` | **Dynamic Read-Only Plugin Inspector:** Call with empty arguments to discover *all* registered RPC services in `omv-engined` and their read-only methods, or pass `rpc_service` + `rpc_method` to query any newly installed plugin while the server blocks all mutating/exec methods. |
| **`omv_get_redacted_config_xml`** | `config_xml` | Complete `/etc/openmediavault/config.xml` tree parsed as JSON with server-side recursive secret redaction. |
| **`omv_get_logs`** | `logs` | Reads up to 500 redacted log lines from `roapi` (plugin audit log), `syslog`, `daemon`, `messages`, `auth`, `smartd`, `smb`, `rsync`, `nut`, `engined`, `nginx`, or `nfs`. |
| **`omv_get_diagnostics`** | `diagnostics` | **Agent Self-Diagnostic & Feedback Tool:** Returns plugin version/config state, enabled vs. disabled scopes, Infisical sync health, live latency probes across 10 core OMV RPC services, and recent Read-Only API log entries. |

---

## Agentic Feedback Loop & Native OMV Log Viewer

### 1. Inline `_agent_feedback` on Every Response
Every API call includes an `_agent_feedback` block so AI agents immediately see execution timing, enabled scopes, and whether any sub-RPC degraded:

```json
"_agent_feedback": {
  "plugin_version": "1.0.0-1",
  "section": "omv_extras",
  "client_ip": "192.168.1.100",
  "timestamp": "2026-10-28T08:00:00-04:00",
  "duration_ms": 22.4,
  "partial_errors_count": 0,
  "partial_errors": [],
  "enabled_scopes": [
    "overview", "disks", "storage", "shares", "ups", "network",
    "apt", "omv_extras", "rpc_inspect", "config_xml", "logs", "diagnostics"
  ],
  "disabled_scopes": [],
  "troubleshooting_hint": "All sub-RPC calls succeeded."
}
```

### 2. Native OMV Web UI Log Viewer (`Diagnostics` -> `System Logs` -> `Logs`)
You can inspect all Read-Only API activity directly inside the OpenMediaVault Web UI under **`Diagnostics` -> `System Logs` -> `Logs` -> `Read-Only API`** (backed by `/var/log/openmediavault-ro-api.log` with automatic 1 MiB rotation).

<!-- SCREENSHOT 4 PLACEHOLDER -->
<!--
![OpenMediaVault Diagnostics -> System Logs -> Read-Only API](docs/images/04-omv-diagnostics-system-logs-roapi.png)
-->

---

## Workbench UI Reference (`Services` -> `Read-Only API`)

### Section 1: General & Access Control
| UI Field | XML Key | Default | Description |
| :--- | :--- | :--- | :--- |
| **Enabled** | `enable` | `true` | Master switch for `RoApiProxy::query`. |
| **Read-Only API token** | `apitoken` | Auto-generated 256-bit hex | Bearer token required to query the API. |
| **Generate new random 256-bit token on save** | `regeneratetoken` | `false` | Generates a fresh 64-character CSPRNG hex token when saving and resets the checkbox to `false`. |
| **Allowed client IPs / subnets** | `allowedips` | `127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16` | Comma-separated IPv4 addresses or CIDR blocks allowed to query the API (`*` allows any IP with a valid token). |
| **Invalid token delay (ms)** | `faildelayms` | `200` (`0`–`5000`) | Brute-force rate-limit delay when an invalid token or unauthorized IP is rejected. |
| **Syslog audit logging** | `auditlog` | `errors_only` | `errors_only` (unauthorized/rejected requests), `all` (every query + rejections), or `off`. |
| **Comment** | `comment` | *(empty)* | Optional note (e.g., which dashboard or MCP agent uses this token). |

### Section 2: Allowed Read-Only Data Scopes & Redaction
Granularly enable or disable any of the 10 read-only scopes (`allow_overview`, `allow_disks`, `allow_storage`, `allow_shares`, `allow_ups`, `allow_network`, `allow_apt`, `allow_omv_extras`, `allow_rpc_inspect`, `allow_configxml`, `allow_logs`, `allow_diagnostics`) or add custom comma-separated key substrings to **`Redacted key patterns`** (`redactpatterns`).

### Section 3: Optional Infisical Universal Auth Token Sync
For homelabs and teams using [**Infisical**](https://infisical.com) (Cloud or self-hosted), check **"Pull token from Infisical"** (`infisicalenable`) to have OpenMediaVault automatically fetch and cache (`/run/openmediavault-ro-api.cache`, `0600`) the expected token using a read-only Machine Identity (`infisicalurl`, `infisicalprojectid`, `infisicalenv`, `infisicalpath`, `infisicalsecretkey`, `infisicalclientid`, `infisicalclientsecret`, `infisicalcachettl`, `infisicalverifyssl`, `infisicalfallback`).

<!-- SCREENSHOT 5 PLACEHOLDER -->
<!--
![Optional Infisical Universal Auth Settings in OMV](docs/images/05-omv-infisical-sync-settings.png)
-->

On the MCP client side, if you use the Infisical CLI, you can omit `OMV_RO_API_TOKEN` from your MCP config and pass `INFISICAL_PROJECT_ID` instead:

```json
"env": {
  "INFISICAL_PROJECT_ID": "your-infisical-project-uuid",
  "INFISICAL_ENV": "prod",
  "INFISICAL_PATH": "/omv"
}
```

---

## Direct `curl` API Usage (Without MCP)

You can also query the Read-Only API directly from any script, monitoring tool, or dashboard via HTTP `POST` to `/rpc.php`:

```bash
curl -sS -X POST "http://192.168.1.50/rpc.php" \
  -H "Content-Type: application/json" \
  -d '{
    "service": "RoApiProxy",
    "method": "query",
    "params": {
      "section": "overview",
      "token": "YOUR_64_CHAR_TOKEN"
    },
    "options": null
  }' | jq .
```

To discover all registered RPC services and their read-only methods via `curl`:

```bash
curl -sS -X POST "http://192.168.1.50/rpc.php" \
  -H "Content-Type: application/json" \
  -d '{
    "service": "RoApiProxy",
    "method": "query",
    "params": {
      "section": "rpc_inspect",
      "rpc_service": "discover",
      "token": "YOUR_64_CHAR_TOKEN"
    },
    "options": null
  }' | jq .
```

---

## Building from Source

```bash
./build-deb.sh
# Output: dist/openmediavault-ro-api_1.0.0-1_all.deb
```

Or using standard Debian build tools:

```bash
dpkg-buildpackage -us -uc -b
```

---

## License

Released under the [GNU General Public License v3.0 or later (GPL-3.0+)](LICENSE), matching upstream OpenMediaVault.
