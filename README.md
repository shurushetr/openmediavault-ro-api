# `openmediavault-ro-api` — Read-Only API & MCP Server for OpenMediaVault 7 / 8

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![OpenMediaVault](https://img.shields.io/badge/OpenMediaVault-7.x%20%7C%208.x-5aa3e8)](https://www.openmediavault.org/)
[![MCP Compatible](https://img.shields.io/badge/MCP-12%20Read--Only%20Tools-10a37f)](https://modelcontextprotocol.io/)

Give AI coding assistants (**Claude Desktop, Claude Code, Cursor, Google Antigravity, VS Code Copilot, Windsurf, Cline**), dashboards, and infrastructure auditors **safe, strictly read-only visibility** into your OpenMediaVault NAS—**without** giving them your `admin` password, SSH root access, or permission to modify anything.

---

## Why Use `openmediavault-ro-api`?

By default, OpenMediaVault's web RPC gateway (`/rpc.php` -> `OMV\Rpc\Proxy\Json::handle()`) enforces an administrator browser session (`OMV\Session::validateAuthentication()`, `OMV_ROLE_ADMINISTRATOR`) for every RPC service except `Session::login`. Giving an AI agent or dashboard your `admin` credentials grants full permission to format disks, delete shared folders, or change passwords.

`openmediavault-ro-api` installs as a native `.deb` plugin inside OpenMediaVault 7 (`sandworm`) / 8 (`synchrony`) and provides a **dedicated, session-free, server-enforced Read-Only endpoint (`/ro-api.php` -> `RoApi::query`)**:

- **Strictly Read-Only by Design:** Exposes zero `set`, `delete`, `applyChanges`, or shell-execution methods to token clients. Even its dynamic plugin inspector (`omv_inspect_rpc`) enforces a server-side allowlist that permits only read-only getters (`get*`, `enumerate*`, `list*`, `is*`, `has*`, `status*`).
- **Automatic Password & Secret Redaction:** Every response is scrubbed inside `omv-engined` *before* it leaves your NAS. Passwords, private keys, API tokens, WireGuard keys, and NUT/SMB secrets are replaced with `***REDACTED***`.
- **Full `omv-extras` Support:** Audits both core OpenMediaVault services and `omv-extras` plugins (Docker Compose, MergerFS, SnapRAID, ZFS, KVM/Libvirt, WireGuard, BorgBackup, RemoteMount, LUKS, MD RAID, iSCSI, CPU Temp, and more).
- **Built for AI Agents:** Includes an inline `_agent_feedback` block on every response plus dedicated `omv_get_diagnostics` and `omv_get_logs` tools so AI agents can self-diagnose permission scopes, service latency, and daemon logs.
- **Native OMV Workbench & Service Integration:** Integrates with **`Services` -> `Read-Only API`**, **`Diagnostics` -> `Services` -> `Overview`** (`Engined\Module\RoApi`), and **`Diagnostics` -> `System Logs` -> `Logs` -> `Read-Only API`**.
- **Safe Uninstall Guarantee:** Removing or purging the plugin **never** deletes your saved settings in `/etc/openmediavault/config.xml`.

<!-- SCREENSHOT 1 PLACEHOLDER -->
<!--
![OpenMediaVault Read-Only API Settings](docs/images/01-omv-ro-api-settings-overview.png)
-->

---

## Quick Start (3 Minutes)

### Step 1: Install the Plugin in OpenMediaVault 7 / 8

Choose any of the three standard OpenMediaVault 7/8 installation methods below:

#### Option A: 1-Line APT Repository Installer (`omv-extras` Style — Recommended)
Run the repository bootstrap script via SSH (or once via **`System` -> `Scheduled Tasks`** as `root`). This installs the GPG keyring (`/usr/share/keyrings/openmediavault-ro-api-keyring.gpg`), registers the DEB822 APT source (`/etc/apt/sources.list.d/openmediavault-ro-api.sources`), and installs `openmediavault-ro-api` so future updates appear automatically in **`System` -> `Update Management`**:
```bash
wget -O - https://shurushetr.github.io/openmediavault-ro-api/install | sudo bash
```

#### Option B: 100% OMV Web UI via `openmediavault-apt` + `System` -> `Plugins`
1. In the OpenMediaVault Web UI, go to **`System` -> `Plugins`**, ensure **`openmediavault-apt`** is installed, and apply changes if prompted.
2. Go to **`System` -> `APT`** (Repositories) and click **`Create`** (`+`):
   - **URI / URL:** `https://shurushetr.github.io/openmediavault-ro-api`
   - **Distribution / Suites:** `sandworm`
   - **Components:** `main`
   - **GPG Key:** Paste the contents of [`openmediavault-ro-api.asc`](https://shurushetr.github.io/openmediavault-ro-api/openmediavault-ro-api.asc)
3. Save and apply the yellow configuration banner.
4. Go to **`System` -> `Plugins`**, click **`Check for new plugins`** (`🔍`), select **`openmediavault-ro-api`**, and click **`Install`** (`⬇`).

<!-- SCREENSHOT 2 PLACEHOLDER -->
<!--
![Installing openmediavault-ro-api in System -> Plugins](docs/images/02-omv-plugin-install.png)
-->

#### Option C: Direct `.deb` Package Install
```bash
curl -fsSL https://github.com/shurushetr/openmediavault-ro-api/releases/latest/download/openmediavault-ro-api_1.0.0-1_all.deb -o /tmp/openmediavault-ro-api.deb && sudo apt-get install -y /tmp/openmediavault-ro-api.deb
```

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

### Step 3: Download the Companion MCP Script (Linux & Windows)

The companion MCP server ([**`mcp/omv-ro-mcp.py`**](mcp/omv-ro-mcp.py)) runs on your workstation (Linux, Windows, or macOS) and requires only **Python 3.8+** standard library—**zero `pip install` dependencies**.

#### Linux (Bash / Zsh)
```bash
mkdir -p ~/.local/bin
curl -fsSL https://raw.githubusercontent.com/shurushetr/openmediavault-ro-api/main/mcp/omv-ro-mcp.py -o ~/.local/bin/omv-ro-mcp.py
chmod +x ~/.local/bin/omv-ro-mcp.py
```

#### Windows (PowerShell)
```powershell
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.local\bin" | Out-Null
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/shurushetr/openmediavault-ro-api/main/mcp/omv-ro-mcp.py" -OutFile "$env:USERPROFILE\.local\bin\omv-ro-mcp.py"
```

---

### Step 4: Configure Your AI Assistant (Linux & Windows Guides)

Choose your AI client below and replace:
- `http://192.168.1.50` with your OpenMediaVault IP or URL
- `YOUR_64_CHAR_TOKEN` with the Read-Only API token from Step 2
- `yourname` with your Linux or Windows username

<details open>
<summary><b>1. Claude Desktop (Linux & Windows)</b></summary>

**Config File Location:**
- **Linux:** `~/.config/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json` (press `Win + R`, paste `%APPDATA%\Claude`, and press Enter)

**Linux Configuration:**
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

**Windows Configuration:**
```json
{
  "mcpServers": {
    "omv-ro": {
      "command": "python",
      "args": ["C:\\Users\\yourname\\.local\\bin\\omv-ro-mcp.py"],
      "env": {
        "OMV_HOST": "http://192.168.1.50",
        "OMV_RO_API_TOKEN": "YOUR_64_CHAR_TOKEN"
      }
    }
  }
}
```
Restart Claude Desktop. You will see the 12 `omv_*` tools under the tools icon.
</details>

<details>
<summary><b>2. Claude Code CLI (Linux & Windows)</b></summary>

**Linux (Bash):**
```bash
claude mcp add omv-ro \
  -e OMV_HOST="http://192.168.1.50" \
  -e OMV_RO_API_TOKEN="YOUR_64_CHAR_TOKEN" \
  -- python3 "$HOME/.local/bin/omv-ro-mcp.py"
```

**Windows (PowerShell):**
```powershell
claude mcp add omv-ro `
  -e OMV_HOST="http://192.168.1.50" `
  -e OMV_RO_API_TOKEN="YOUR_64_CHAR_TOKEN" `
  -- python "$env:USERPROFILE\.local\bin\omv-ro-mcp.py"
```
Verify with `claude mcp list`.
</details>

<details>
<summary><b>3. Cursor IDE (Linux & Windows)</b></summary>

Open **Cursor Settings** -> **MCP** -> **Add new global MCP server**, or edit:
- **Linux:** `~/.cursor/mcp.json`
- **Windows:** `%USERPROFILE%\.cursor\mcp.json`

**Linux Configuration:**
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

**Windows Configuration:**
```json
{
  "mcpServers": {
    "omv-ro": {
      "command": "python",
      "args": ["C:\\Users\\yourname\\.local\\bin\\omv-ro-mcp.py"],
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
<summary><b>4. Google Antigravity (AGY) & Gemini CLI (Linux & Windows)</b></summary>

**Config File Location:**
- **Linux:** `~/.gemini/config/mcp_config.json` (Antigravity) or `~/.gemini/settings.json` (Gemini CLI)
- **Windows:** `%USERPROFILE%\.gemini\config\mcp_config.json` (Antigravity) or `%USERPROFILE%\.gemini\settings.json` (Gemini CLI)

**Linux Configuration:**
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

**Windows Configuration:**
```json
{
  "mcpServers": {
    "omv-ro": {
      "command": "python",
      "args": ["C:\\Users\\yourname\\.local\\bin\\omv-ro-mcp.py"],
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
<summary><b>5. VS Code — GitHub Copilot Agent Mode / Cline / Roo Code (Linux & Windows)</b></summary>

For **VS Code Copilot Agent Mode**, add to `.vscode/mcp.json` (or your User `settings.json` under `"mcp": { "servers": { ... } }`):

**Linux Configuration:**
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

**Windows Configuration:**
```json
{
  "servers": {
    "omv-ro": {
      "type": "stdio",
      "command": "python",
      "args": ["C:\\Users\\yourname\\.local\\bin\\omv-ro-mcp.py"],
      "env": {
        "OMV_HOST": "http://192.168.1.50",
        "OMV_RO_API_TOKEN": "YOUR_64_CHAR_TOKEN"
      }
    }
  }
}
```

For **Cline / Roo Code**, open **MCP Servers** -> **Configure MCP Servers** (`cline_mcp_settings.json`) and use the same `mcpServers` block as Claude Desktop above.
</details>

<details>
<summary><b>6. Windsurf IDE (Linux & Windows)</b></summary>

**Config File Location:**
- **Linux:** `~/.codeium/windsurf/mcp_config.json`
- **Windows:** `%USERPROFILE%\.codeium\windsurf\mcp_config.json`

Use the same `mcpServers` JSON block shown in the Claude Desktop / Cursor section above (`"command": "python3"` on Linux, `"command": "python"` on Windows).
</details>

<details>
<summary><b>Security Tip: Keep Your Token Out of <code>mcp_config.json</code> (Local Token File on Linux & Windows)</b></summary>

If you don't want your token stored in plaintext inside your IDE's MCP config file, store it in a user-restricted token file and pass `OMV_RO_API_TOKEN_FILE`:

**Linux:**
```bash
mkdir -p ~/.config/omv-ro
printf "%s" "YOUR_64_CHAR_TOKEN" > ~/.config/omv-ro/token
chmod 600 ~/.config/omv-ro/token
```

**Windows (PowerShell):**
```powershell
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.config\omv-ro" | Out-Null
Set-Content -NoNewline -Path "$env:USERPROFILE\.config\omv-ro\token" -Value "YOUR_64_CHAR_TOKEN"
icacls "$env:USERPROFILE\.config\omv-ro\token" /inheritance:r /grant:r "$($env:USERNAME):R"
```

Then reference `OMV_RO_API_TOKEN_FILE` in your MCP config (works on both Linux and Windows):

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
| **Enabled** | `enable` | `true` | Master switch for `/ro-api.php` (`RoApi::query`). |
| **Read-Only API token** | `apitoken` | Auto-generated 256-bit hex | Bearer token required to query the API. |
| **Generate new random 256-bit token on save** | `regeneratetoken` | `false` | Generates a fresh 64-character CSPRNG hex token when saving and resets the checkbox to `false`. |
| **Allowed client IPs / subnets** | `allowedips` | `127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16` | Comma-separated IPv4 addresses or CIDR blocks allowed to query the API (`*` allows any IP with a valid token). |
| **Invalid token delay (ms)** | `faildelayms` | `200` (`0`–`5000`) | Brute-force rate-limit delay when an invalid token or unauthorized IP is rejected. |
| **Syslog audit logging** | `auditlog` | `errors_only` | `errors_only` (unauthorized/rejected requests), `all` (every query + rejections), or `off`. |
| **Comment** | `comment` | *(empty)* | Optional note (e.g., which dashboard or MCP agent uses this token). |

### Section 2: Allowed Read-Only Data Scopes & Redaction
Granularly enable or disable any of the 12 read-only scopes (`allow_overview`, `allow_disks`, `allow_storage`, `allow_shares`, `allow_ups`, `allow_network`, `allow_apt`, `allow_omv_extras`, `allow_rpc_inspect`, `allow_configxml`, `allow_logs`, `allow_diagnostics`) or add custom comma-separated key substrings to **`Redacted key patterns`** (`redactpatterns`).

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

## Direct HTTP API Usage (Without MCP)

You can also query `/ro-api.php` directly from any script, monitoring tool, or dashboard via HTTP `POST` or `GET`:

#### Linux (`curl` — POST JSON-RPC or GET with Bearer Header)
```bash
# Option 1: Simple GET with Authorization: Bearer header
curl -sS "http://192.168.1.50/ro-api.php?section=overview" \
  -H "Authorization: Bearer YOUR_64_CHAR_TOKEN" | jq .

# Option 2: JSON-RPC POST body
curl -sS -X POST "http://192.168.1.50/ro-api.php" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_64_CHAR_TOKEN" \
  -d '{
    "service": "RoApi",
    "method": "query",
    "params": {
      "section": "overview"
    }
  }' | jq .
```

#### Windows (`PowerShell`)
```powershell
$headers = @{
  Authorization = "Bearer YOUR_64_CHAR_TOKEN"
}
Invoke-RestMethod -Method Get -Uri "http://192.168.1.50/ro-api.php?section=overview" -Headers $headers | ConvertTo-Json -Depth 6
```

---

## Repository Structure (Canonical OpenMediaVault 7 / 8 Plugin Layout)

```text
openmediavault-ro-api/
├── debian/                                                       # Debian packaging (debhelper / dpkg-buildpackage)
│   ├── changelog
│   ├── control                                                   # Section: utils, XB-Plugin-Section: utilities
│   ├── copyright
│   ├── install                                                   # Maps etc/, srv/, usr/, var/ into package root
│   ├── openmediavault-ro-api.postinst                            # Runs omv-confdbadm create & configures nginx socket
│   ├── openmediavault-ro-api.postrm                              # Non-destructive removal (preserves config.xml)
│   ├── openmediavault-ro-api.triggers                            # activate-noawait update-workbench / restart-engined
│   └── rules
├── etc/nginx/openmediavault-webgui.d/openmediavault-ro-api.conf  # Routes /ro-api.php to OMV WebGUI PHP-FPM socket
├── srv/salt/omv/deploy/roapi/default.sls                         # SaltStack deployment state (omv-salt deploy run roapi)
├── usr/share/openmediavault/
│   ├── confdb/create.d/conf.service.roapi.sh                     # Seeds /config/services/roapi in config.xml
│   ├── datamodels/
│   │   ├── conf.service.roapi.json                               # Config database JSON schema
│   │   └── rpc.roapi.json                                        # RPC parameter validation schemas
│   ├── engined/
│   │   ├── inc/90roapi-logfile.inc                               # LogFileSpec registration for System Logs UI
│   │   ├── module/roapi.inc                                      # Engined\Module\RoApi (IServiceStatus)
│   │   └── rpc/roapi.inc                                         # OMVRpcServiceRoApi (get, set, query)
│   └── workbench/
│       ├── component.d/omv-services-roapi-form-page.yaml         # Services -> Read-Only API form
│       ├── log.d/roapi.yaml                                      # Diagnostics -> System Logs -> Read-Only API
│       ├── navigation.d/services.roapi.yaml                      # Workbench sidebar navigation item
│       └── route.d/services.roapi.yaml                           # Angular Workbench route definition
├── var/www/openmediavault/ro-api.php                             # Session-free token-authenticated HTTP entry point
├── mcp/omv-ro-mcp.py                                             # Zero-dependency Python MCP server (Linux & Windows)
├── scripts/build-apt-repo.sh                                     # Builds GPG-signed Debian APT repository (DEB822)
└── build-deb.sh                                                  # Standalone .deb builder
```

---

## Building from Source

On Debian / Ubuntu (or WSL2 on Windows):

```bash
# Build .deb package
./build-deb.sh
# Output: dist/openmediavault-ro-api_1.0.0-1_all.deb

# Build signed Debian APT repository (dists/sandworm, bookworm, synchrony, trixie)
./scripts/build-apt-repo.sh dist/openmediavault-ro-api_1.0.0-1_all.deb dist/apt-repo
```

Or using standard Debian build tools:

```bash
dpkg-buildpackage -us -uc -b
```

---

## License

Released under the [GNU General Public License v3.0 or later (GPL-3.0+)](LICENSE), matching upstream OpenMediaVault.
