# wireguard-ui
A web user interface to manage your WireGuard setup.

## Features
- Friendly UI
- Authentication
- Manage extra client's information (name, email, etc)
- Retrieve configs using QR code / file

## Run WireGuard-UI
Only docker option for now, please refer to this example of [docker-compose.yml](https://github.com/ngoduykhanh/wireguard-ui/blob/master/docker-compose.yaml).

Please adjust volume mount points to work with your setup. Then run it:

```
docker-compose up
```

## Auto restart WireGuard daemon
WireGuard-UI only takes care of configuration generation. You can use systemd to watch for the changes and restart the service. Following is an example:

Create /etc/systemd/system/wgui.service

```
[Unit]
Description=Restart WireGuard
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl restart wg-quick@wg0.service
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

## Screenshot

![wireguard-ui](https://user-images.githubusercontent.com/6447444/80270680-76adf980-86e4-11ea-8ca1-9237f0dfa249.png)

## License
MIT. See [LICENSE](https://github.com/ngoduykhanh/wireguard-ui/blob/master/LICENSE).
