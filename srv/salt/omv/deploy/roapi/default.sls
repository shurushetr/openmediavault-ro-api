# This file is part of OpenMediaVault Read-Only API (openmediavault-ro-api).
#
# @license   https://www.gnu.org/licenses/gpl-3.0.html GPL Version 3
# @author    shurushetr <shurushetr@gmail.com>
# @copyright Copyright (c) 2026 shurushetr

configure_roapi_logfile:
  file.managed:
    - name: "/var/log/openmediavault-ro-api.log"
    - user: root
    - group: adm
    - mode: "0640"
    - replace: False
