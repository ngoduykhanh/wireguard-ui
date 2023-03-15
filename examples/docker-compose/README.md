## Prerequisites

### Kernel Module

Depending on if the Wireguard kernel module is available on your system you have more or less choices which example to use.

You can check if the kernel modules are available via the following command:
```shell
modprobe wireguard
```

If the command exits successfully and doesn't print an error the kernel modules are available.
If it does error, you either have to install them manually (or activate if deactivated) or use an userspace implementation.
For an example of an userspace implementation, see _borigtun_.

### Credentials

Username and password for all examples is `admin` by default.
For security reasons it's highly recommended to change them before the first startup.

## Examples
- **[system](system.yml)**

  If you have Wireguard already installed on your system and only want to run the UI in docker this might fit the most.
- **[linuxserver](linuxserver.yml)**

  If you have the Wireguard kernel modules installed (included in the mainline kernel since version 5.6) but want it running inside of docker, this might fit the most.
- **[boringtun](boringtun.yml)**

  If Wireguard kernel modules are not available, you can switch to an userspace implementation like [boringtun](https://github.com/cloudflare/boringtun).
