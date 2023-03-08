# import wg0.conf to the database
import sys
import requests
import json
import configparser
import re

# usage:
# python import-wg-conf.py <wg0.conf> http://<ip>:<port> USER PASSWORD

# parse the command line
if len(sys.argv) != 5:
    print("Usage: python import-wg-conf.py <wg0.conf> http://<ip>:<port> USER PASSWORD")
    sys.exit(1)

# read the config file
with open(sys.argv[1], 'r') as f:
    config_str = f.read()

# we need to use a trick:
# - toml can't parse the IP address
# - configparser will complain about multiple Peer sections
# we will replace [Peer] with [Peer1], [Peer2], etc.

# first, count the number of peers
peers = re.findall(r'\[Peer\]', config_str)
num_peers = len(peers)
# then replace [Peer] with [Peer1], [Peer2], etc.
for i in range(num_peers):
    config_str = config_str.replace('[Peer]', '[Peer' + str(i+1) + ']', 1)

# remove the comment from '# friendly_name = ' line
config_str = config_str.replace('# friendly_name = ', 'friendly_name = ')

# parse the config file
config = configparser.ConfigParser()
config.read_string(config_str)

# iterate the sections
for section in config.sections():
    # print header
    print('[' + section + ']')
    # iterate the options
    for option in config.options(section):
        print(option + ' = ' + config[section][option])
    print('')

# login to the API

login_data = {
    'username': sys.argv[3],
    'password': sys.argv[4],
}

session = requests.Session()

response = session.post(sys.argv[2] + '/login', json=login_data)


# add the peers to wireguard-ui

# iterate the sections
for section in config.sections():
    #if starts with "Peer"
    if not section.startswith('Peer'):
        continue

    newclient_data = {
        'name': 'clientname',
        'email': '',
        'allocated_ips': [
        ],
        'allowed_ips': [
            '10.123.0.0/24', 
            '172.16.0.0/12'
        ],
        'extra_allowed_ips': [],
        'use_server_dns': True,
        'enabled': True,
        'public_key': '',
        'preshared_key': '',
    }

    for option in config.options(section):
        if option == 'friendly_name':
            newclient_data['name'] = config[section][option]
        elif option == 'allowedips':
            # this will become AllowedIPs in the configuration file
            newclient_data['allocated_ips'] = config[section][option].split(',')
        elif option == 'publickey':
            newclient_data['public_key'] = config[section][option]
        elif option == 'presharedkey':
            newclient_data['preshared_key'] = config[section][option]

    response = session.post('http://localhost:5000/new-client',  json=newclient_data)
    print(response.text)
    #break

