#!/usr/bin/env dash
set -e

. /usr/share/openmediavault/scripts/helper-functions

if ! omv_config_exists "/config/services/roapi"; then
	default_token="__INITIAL_RO_TOKEN__"
	if [ -z "${default_token}" ] || [ "${default_token}" = "__INITIAL_RO_TOKEN__" ]; then
		default_token=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
	fi
	omv_config_add_node "/config/services" "roapi"
	omv_config_add_key "/config/services/roapi" "enable" "1"
	omv_config_add_key "/config/services/roapi" "apitoken" "${default_token}"
	omv_config_add_key "/config/services/roapi" "regeneratetoken" "0"
	omv_config_add_key "/config/services/roapi" "allowedips" "127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"
	omv_config_add_key "/config/services/roapi" "faildelayms" "200"
	omv_config_add_key "/config/services/roapi" "auditlog" "errors_only"
	omv_config_add_key "/config/services/roapi" "comment" ""
	omv_config_add_key "/config/services/roapi" "allow_overview" "1"
	omv_config_add_key "/config/services/roapi" "allow_disks" "1"
	omv_config_add_key "/config/services/roapi" "allow_storage" "1"
	omv_config_add_key "/config/services/roapi" "allow_shares" "1"
	omv_config_add_key "/config/services/roapi" "allow_ups" "1"
	omv_config_add_key "/config/services/roapi" "allow_network" "1"
	omv_config_add_key "/config/services/roapi" "allow_apt" "1"
	omv_config_add_key "/config/services/roapi" "allow_configxml" "1"
	omv_config_add_key "/config/services/roapi" "redactpatterns" "password,passwd,secret,token,apitoken,privatekey,passphrase,shadow,psk,key"
	omv_config_add_key "/config/services/roapi" "infisicalenable" "0"
	omv_config_add_key "/config/services/roapi" "infisicalurl" "https://app.infisical.com"
	omv_config_add_key "/config/services/roapi" "infisicalprojectid" ""
	omv_config_add_key "/config/services/roapi" "infisicalenv" "prod"
	omv_config_add_key "/config/services/roapi" "infisicalpath" "/omv"
	omv_config_add_key "/config/services/roapi" "infisicalsecretkey" "OMV_RO_API_TOKEN"
	omv_config_add_key "/config/services/roapi" "infisicalclientid" ""
	omv_config_add_key "/config/services/roapi" "infisicalclientsecret" ""
	omv_config_add_key "/config/services/roapi" "infisicalcachettl" "300"
	omv_config_add_key "/config/services/roapi" "infisicalverifyssl" "1"
	omv_config_add_key "/config/services/roapi" "infisicalfallback" "1"
fi

exit 0
