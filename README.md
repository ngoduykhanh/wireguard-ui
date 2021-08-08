![](https://github.com/ngoduykhanh/wireguard-ui/workflows/wireguard-ui%20build%20release/badge.svg)

# wireguard-ui

A web user interface to manage your WireGuard setup.

## Features
- Friendly UI
- Authentication
- Manage extra client's information (name, email, etc)
- Retrieve configs using QR code / file

## Run WireGuard-UI

Default username and password are `admin`.

### Using docker compose

You can take a look at this example of [docker-compose.yml](https://github.com/ngoduykhanh/wireguard-ui/blob/master/docker-compose.yaml). Please adjust volume mount points to work with your setup. Then run it like below:

```
docker-compose up
```
### Environment Variables


Set the `SESSION_SECRET` environment variable to a random value.

In order to sent the wireguard configuration to clients via email (using sendgrid api) set the following environment variables

```
SENDGRID_API_KEY: Your sendgrid api key
EMAIL_FROM: the email address you registered on sendgrid
EMAIL_FROM_NAME: the sender's email address
```

### Using binary file

Download the binary file from the release and run it with command:

```
./wireguard-ui
```

## Auto restart WireGuard daemon
WireGuard-UI only takes care of configuration generation. You can use systemd to watch for the changes and restart the service. Following is an example:

### systemd

Create /etc/systemd/system/wgui.service

```
[Unit]
Description=Restart WireGuard
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl restart wg-quick@wg0.service

[Install]
RequiredBy=wgui.path
```

Create /etc/systemd/system/wgui.path

```
[Unit]
Description=Watch /etc/wireguard/wg0.conf for changes

[Path]
PathModified=/etc/wireguard/wg0.conf

[Install]
WantedBy=multi-user.target
```

Apply it

```
systemctl enable wgui.{path,service}
systemctl start wgui.{path,service}
```

### openrc

Create and `chmod +x` /usr/local/bin/wgui
```
#!/bin/sh
wg-quick down wg0
wg-quick up wg0
```

Create and `chmod +x` /etc/init.d/wgui
```
#!/sbin/openrc-run

command=/sbin/inotifyd
command_args="/usr/local/bin/wgui /etc/wireguard/wg0.conf:w"
pidfile=/run/${RC_SVCNAME}.pid
command_background=yes
```

Apply it

```
rc-service wgui start
rc-update add wgui default
```

## Build

### Build docker image

Go to the project root directory and run the following command:

```
docker build -t wireguard-ui .
```

### Build binary file

Prepare the assets directory

```
./prepare_assets.sh
```

Then you can embed resources by generating Go source code

```
rice embed-go
go build -o wireguard-ui
```

Or, append resources to executable as zip file

```
go build -o wireguard-ui
rice append --exec wireguard-ui
```

## Screenshot

![wireguard-ui](https://user-images.githubusercontent.com/6447444/80270680-76adf980-86e4-11ea-8ca1-9237f0dfa249.png)

## License
MIT. See [LICENSE](https://github.com/ngoduykhanh/wireguard-ui/blob/master/LICENSE).

## Support
If you like the project and want to support it, you can *buy me a coffee* ☕

<a href="https://www.buymeacoffee.com/khanhngo" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174"></a>
