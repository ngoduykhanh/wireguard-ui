#!/bin/bash

config="/etc/wireguard/wg0.conf"
old_config="/etc/wireguard/wg0.conf.old"

if [ ! -f $old_config ]; then
    awk '/Interface/,/# ID:/' $config | head -n -1 | tail -n +2 > $old_config
    echo "No old config found, restarting wireguard (wg-quick)"
    wg-quick down wg0
    systemctl restart wg-quick@wg0.service
    exit 0
fi

difference=$(diff <(awk '/Interface/,/# ID:/' $config | head -n -1 | tail -n +2) <(cat $old_config))

if [ -n "$difference" ]; then
    awk '/Interface/,/# ID:/' $config | head -n -1 | tail -n +2 > $old_config
    echo "Changes to interface detected, restarting wireguard (wg-quick)"
    wg-quick down wg0
    systemctl restart wg-quick@wg0.service
    exit 0
else
    awk '/Interface/,/# ID:/' $config | head -n -1 | tail -n +2 > $old_config
    echo "No changes to interface detected, restarting wireguard (wg syncconf)"
    wg syncconf wg0 <(wg-quick strip wg0)
    exit 0
fi
