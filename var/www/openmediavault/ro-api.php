<?php
/**
 * This file is part of OpenMediaVault Read-Only API (openmediavault-ro-api).
 *
 * @license   https://www.gnu.org/licenses/gpl-3.0.html GPL Version 3
 * @author    shurushetr <shurushetr@gmail.com>
 * @copyright Copyright (c) 2026 shurushetr
 *
 * Dedicated session-free JSON-RPC / REST entry point for `RoApi::query`.
 *
 * Why this file exists instead of `/var/www/openmediavault/rpc.php`:
 * Upstream `/usr/share/php/openmediavault/rpc/proxy/json.inc` calls
 * `$session->validateAuthentication()` at line 80 for every RPC service except
 * `Session::login`, rejecting unauthenticated calls before they ever reach
 * `omv-engined`. This entry point accepts token-authenticated Read-Only API
 * queries directly and forwards them strictly to `RoApi::query` over
 * `omv-engined` (`\OMV\Rpc\Rpc::MODE_REMOTE`).
 */
try {
    require_once("openmediavault/autoloader.inc");
    require_once("openmediavault/globals.inc");
    require_once("openmediavault/functions.inc");

    header("Content-Type: application/json; charset=utf-8");
    header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
    header("X-Content-Type-Options: nosniff");

    $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
    if ($method === 'OPTIONS') {
        http_response_code(204);
        exit;
    }

    if (!in_array($method, ['POST', 'GET'], true)) {
        http_response_code(405);
        echo json_encode([
            "response" => null,
            "error" => [
                "code" => 405,
                "message" => "Method not allowed. Use POST or GET."
            ]
        ], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $params = [];
    if ($method === 'POST') {
        $rawBody = file_get_contents("php://input");
        if (is_string($rawBody) && trim($rawBody) !== '') {
            $decoded = json_decode($rawBody, true);
            if (!is_array($decoded)) {
                http_response_code(400);
                echo json_encode([
                    "response" => null,
                    "error" => [
                        "code" => 400,
                        "message" => "Invalid JSON request body."
                    ]
                ], JSON_UNESCAPED_SLASHES);
                exit;
            }
            // Accept both standard OMV JSON-RPC envelope {"service":"RoApi","method":"query","params":{...}}
            // and direct parameter objects {"section":"overview","token":"..."}
            if (isset($decoded['params']) && is_array($decoded['params'])) {
                if (!empty($decoded['service']) && !in_array($decoded['service'], ['RoApi', 'RoApiProxy'], true)) {
                    http_response_code(403);
                    echo json_encode([
                        "response" => null,
                        "error" => [
                            "code" => 403,
                            "message" => "Only service 'RoApi' method 'query' is permitted on /ro-api.php."
                        ]
                    ], JSON_UNESCAPED_SLASHES);
                    exit;
                }
                if (!empty($decoded['method']) && $decoded['method'] !== 'query') {
                    http_response_code(403);
                    echo json_encode([
                        "response" => null,
                        "error" => [
                            "code" => 403,
                            "message" => "Only method 'query' is permitted on /ro-api.php."
                        ]
                    ], JSON_UNESCAPED_SLASHES);
                    exit;
                }
                $params = $decoded['params'];
            } else {
                $params = $decoded;
            }
        }
    }

    // Merge GET query parameters if not already present in POST body
    foreach (['section', 'token', 'devicefile', 'logfile', 'limit', 'rpc_service', 'rpc_method', 'rpc_params'] as $key) {
        if (!isset($params[$key]) && isset($_GET[$key])) {
            $params[$key] = ($key === 'limit') ? (int)$_GET[$key] : (string)$_GET[$key];
        }
    }

    // Extract Bearer token from Authorization header or X-OMV-RO-Token header
    if (empty($params['token'])) {
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        if (preg_match('/^Bearer\s+(\S+)$/i', $authHeader, $matches)) {
            $params['token'] = $matches[1];
        } elseif (!empty($_SERVER['HTTP_X_OMV_RO_TOKEN'])) {
            $params['token'] = trim((string)$_SERVER['HTTP_X_OMV_RO_TOKEN']);
        }
    }

    $params['_client_ip'] = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

    $context = [
        "username" => "admin",
        "role" => OMV_ROLE_ADMINISTRATOR
    ];

    $response = \OMV\Rpc\Rpc::call(
        "RoApi",
        "query",
        $params,
        $context,
        \OMV\Rpc\Rpc::MODE_REMOTE,
        true
    );

    echo json_encode([
        "response" => $response,
        "error" => null
    ], JSON_UNESCAPED_SLASHES);
} catch (\Throwable $e) {
    $code = (int)$e->getCode();
    $httpCode = ($code >= 400 && $code < 600) ? $code : 500;
    http_response_code($httpCode);
    echo json_encode([
        "response" => null,
        "error" => [
            "code" => $code,
            "message" => $e->getMessage()
        ]
    ], JSON_UNESCAPED_SLASHES);
}
