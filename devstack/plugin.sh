#!/usr/bin/env bash

# devstack plugin for octavia
GET_PIP_CACHE_LOCATION=/opt/stack/cache/files/get-pip.py

# [api_settings]
#enabled_provider_drivers = amphora:'The Octavia Amphora driver.',ovn:'Octavia OVN driver.'

function _configure_provider_driver {
    iniset ${OCTAVIA_CONF} api_settings enabled_provider_drivers ${OCTAVIA_PROVIDER_DRIVERS}
}

function is_ovn_enabled {
    [[ $NEUTRON_AGENT == "ovn" ]] && return 0
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
