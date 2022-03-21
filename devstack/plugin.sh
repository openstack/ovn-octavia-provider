#!/usr/bin/env bash

# devstack plugin for octavia
GET_PIP_CACHE_LOCATION=/opt/stack/cache/files/get-pip.py

# How to connect to ovsdb-server hosting the OVN NB database
if is_service_enabled tls-proxy; then
   OVN_PROTO=ssl
else
   OVN_PROTO=tcp
fi
OVN_NB_REMOTE=${OVN_NB_REMOTE:-$OVN_PROTO:$SERVICE_HOST:6641}
OVN_SB_REMOTE=${OVN_SB_REMOTE:-$OVN_PROTO:$SERVICE_HOST:6642}

function _configure_provider_driver {
    iniset ${OCTAVIA_CONF} api_settings enabled_provider_drivers "${OCTAVIA_PROVIDER_DRIVERS}"
    iniset ${OCTAVIA_CONF} driver_agent enabled_provider_agents ${OCTAVIA_PROVIDER_AGENTS}
    iniset ${OCTAVIA_CONF} ovn ovn_nb_connection "$OVN_NB_REMOTE"
    iniset ${OCTAVIA_CONF} ovn ovn_sb_connection "$OVN_SB_REMOTE"

    if is_service_enabled tls-proxy; then
        iniset ${OCTAVIA_CONF} ovn ovn_nb_connection "$OVN_NB_REMOTE"
        iniset ${OCTAVIA_CONF} ovn ovn_nb_ca_cert "$INT_CA_DIR/ca-chain.pem"
        iniset ${OCTAVIA_CONF} ovn ovn_nb_certificate "$INT_CA_DIR/$DEVSTACK_CERT_NAME.crt"
        iniset ${OCTAVIA_CONF} ovn ovn_nb_private_key "$INT_CA_DIR/private/$DEVSTACK_CERT_NAME.key"
        iniset ${OCTAVIA_CONF} ovn ovn_sb_connection "$OVN_SB_REMOTE"
        iniset ${OCTAVIA_CONF} ovn ovn_sb_ca_cert "$INT_CA_DIR/ca-chain.pem"
        iniset ${OCTAVIA_CONF} ovn ovn_sb_certificate "$INT_CA_DIR/$DEVSTACK_CERT_NAME.crt"
        iniset ${OCTAVIA_CONF} ovn ovn_sb_private_key "$INT_CA_DIR/private/$DEVSTACK_CERT_NAME.key"
    fi
}

function is_ovn_enabled {
    if [[ $NEUTRON_AGENT == "ovn" || $Q_AGENT == "ovn" ]]; then
        return 0
    fi
    return 1
}

function _install_provider_driver {
   setup_develop $OVN_OCTAVIA_PROVIDER_DIR
}

if [[ "$1" == "stack" ]]; then
    case "$2" in
        post-config)
            if is_ovn_enabled; then
                _configure_provider_driver
            fi
        ;;
        install)
            if is_ovn_enabled; then
                _install_provider_driver
            fi
        ;;
    esac
fi
