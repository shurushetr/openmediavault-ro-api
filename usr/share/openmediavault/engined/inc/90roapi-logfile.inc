<?php
/**
 * Register the Read-Only API log file specification for the OMV Workbench UI
 * (Diagnostics -> System Logs -> Logs -> Read-Only API).
 *
 * @license   https://www.gnu.org/licenses/gpl-3.0.html GPL Version 3
 * @author    shurushetr <shurushetr@gmail.com>
 * @copyright Copyright (c) 2026 shurushetr
 */
require_once("openmediavault/functions.inc");

if (class_exists("\\OMV\\System\\LogFileSpec")) {
    \OMV\System\LogFileSpec::registerSpecification("roapi", [
        "filename" => "openmediavault-ro-api.log",
        "filepath" => "/var/log/openmediavault-ro-api.log",
        "regex" => "/^(\\S+)\\s+(\\S+)\\s+\\[([^\\]]+)\\]\\s+(\\S+)\\s+(.*)$/",
        "columns" => [
            "ts" => [
                "index" => 1,
                "func" => function ($v) {
                    return strtotime($v);
                }
            ],
            "date" => [
                "index" => 1,
                "func" => function ($v) {
                    return date("Y-m-d H:i:s", strtotime($v));
                }
            ],
            "level" => [
                "index" => 2
            ],
            "component" => [
                "index" => 3
            ],
            "client" => [
                "index" => 4
            ],
            "message" => [
                "index" => 5
            ]
        ]
    ]);
}
