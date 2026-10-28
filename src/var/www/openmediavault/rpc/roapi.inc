<?php
/**
 * Local JSON-RPC proxy for openmediavault-ro-api.
 * Loaded by /var/www/openmediavault/rpc.php so token-authenticated Read-Only
 * requests can call RoApiProxy::query without requiring an admin browser session.
 */
class OMVRpcServiceRoApiProxy extends \OMV\Rpc\ServiceAbstract
{
    public function getName()
    {
        return "RoApiProxy";
    }

    public function initialize()
    {
        $this->registerMethod("query");
    }

    public function query($params, $context)
    {
        if (!is_array($params)) {
            $params = [];
        }

        // Support token via Authorization: Bearer <token> or X-OMV-RO-Token header
        if (empty($params['token'])) {
            $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
            if (preg_match('/^Bearer\s+(\S+)$/i', $authHeader, $matches)) {
                $params['token'] = $matches[1];
            } elseif (!empty($_SERVER['HTTP_X_OMV_RO_TOKEN'])) {
                $params['token'] = trim($_SERVER['HTTP_X_OMV_RO_TOKEN']);
            }
        }

        $params['_client_ip'] = $_SERVER['REMOTE_ADDR'] ?? '';

        return \OMV\Rpc\Rpc::call(
            "RoApi",
            "query",
            $params,
            $this->getAdminContext(),
            \OMV\Rpc\Rpc::MODE_REMOTE,
            true
        );
    }
}
