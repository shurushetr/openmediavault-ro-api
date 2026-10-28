<?php
/**
 * This file is part of OpenMediaVault Read-Only API (openmediavault-ro-api).
 *
 * @license   https://www.gnu.org/licenses/gpl-3.0.html GPL Version 3
 * @author    shurushetr <shurushetr@gmail.com>
 * @copyright Copyright (c) 2026 shurushetr
 */
namespace Engined\Module;

class RoApi extends \OMV\Engine\Module\ServiceAbstract
    implements \OMV\Engine\Module\IServiceStatus
{
    public function getName()
    {
        return "roapi";
    }

    public function getStatus()
    {
        $db = \OMV\Config\Database::getInstance();
        $object = $db->get("conf.service.roapi");
        $enabled = (bool)$object->get("enable");
        return [
            "name" => $this->getName(),
            "title" => gettext("Read-Only API"),
            "enabled" => $enabled,
            "running" => $enabled
        ];
    }
}
