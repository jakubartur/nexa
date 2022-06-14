# Sample init scripts and service configuration for nexad

Sample scripts and configuration files for systemd, Upstart and OpenRC
can be found in the contrib/init folder.

    contrib/init/nexad.service:    systemd service unit configuration
    contrib/init/nexad.openrc:     OpenRC compatible SysV style init script
    contrib/init/nexad.openrcconf: OpenRC conf.d file
    contrib/init/nexad.conf:       Upstart service configuration file
    contrib/init/nexad.init:       CentOS compatible SysV style init script

## Service User

All three Linux startup configurations assume the existence of a "nexa" user
and group.  They must be created before attempting to use these scripts.
The OS X configuration assumes nexad will be set up for the current user.

## Configuration

At a bare minimum, nexad requires that the rpcpassword setting be set
when running as a daemon.  If the configuration file does not exist or this
setting is not set, nexad will shutdown promptly after startup.

This password does not have to be remembered or typed as it is mostly used
as a fixed token that nexad and client programs read from the configuration
file, however it is recommended that a strong and secure password be used
as this password is security critical to securing the wallet should the
wallet be enabled.

If nexad is run with the "-server" flag (set by default), and no rpcpassword is set,
it will use a special cookie file for authentication. The cookie is generated with random
content when the daemon starts, and deleted when it exits. Read access to this file
controls who can access it through RPC.

By default the cookie is stored in the data directory, but it's location can be overridden
with the option '-rpccookiefile'.

This allows for running nexad without having to do any manual configuration.

`conf`, `pid`, and `wallet` accept relative paths which are interpreted as
relative to the data directory. `wallet` *only* supports relative paths.

For an example configuration file that describes the configuration settings,
see `contrib/debian/examples/nexa.conf`.

## Paths

### Linux

All three configurations assume several paths that might need to be adjusted.

Binary:              `/usr/bin/nexad`  
Configuration file:  `/etc/nexa/nexa.conf`  
Data directory:      `/var/lib/nexad`  
PID file:            `/var/run/nexad/nexad.pid` (OpenRC and Upstart) or `/var/lib/nexad/nexad.pid` (systemd)  
Lock file:           `/var/lock/subsys/nexad` (CentOS)  

The configuration file, PID directory (if applicable) and data directory
should all be owned by the nexa user and group.  It is advised for security
reasons to make the configuration file and data directory only readable by the
nexa user and group.  Access to nexa-cli and other nexad rpc clients
can then be controlled by group membership.

### Mac OS X

Binary:              `/usr/local/bin/nexad`  
Configuration file:  `~/Library/Application Support/nexa/nexa.conf`  
Data directory:      `~/Library/Application Support/nexa`
Lock file:           `~/Library/Application Support/nexa/.lock`

## Installing Service Configuration

### systemd (for Debian/Ubuntu based distributions)

Installing this .service file consists of just copying it to
/usr/lib/systemd/system directory, followed by the command
`systemctl daemon-reload` in order to update running systemd configuration.

To test, run `systemctl start nexad` and to enable for system startup run
`systemctl enable nexad`

### OpenRC

Rename nexad.openrc to nexad and drop it in /etc/init.d.  Double
check ownership and permissions and make it executable.  Test it with
`/etc/init.d/nexad start` and configure it to run on startup with
`rc-update add nexad`

### Upstart

Drop nexad.conf in /etc/init.  Test by running `service nexad start`
it will automatically start on reboot.

### CentOS

Copy nexad.init to /etc/init.d/nexad. Test by running `service nexad start`.

Using this script, you can adjust the path and flags to the nexad program by
setting the NEXAD and FLAGS environment variables in the file
/etc/sysconfig/nexad. You can also use the DAEMONOPTS environment variable here.

### Mac OS X

Copy org.nexa.nexad.plist into ~/Library/LaunchAgents. Load the launch agent by
running `launchctl load ~/Library/LaunchAgents/org.nexa.nexad.plist`.

This Launch Agent will cause nexad to start whenever the user logs in.

NOTE: This approach is intended for those wanting to run nexad as the current user.
You will need to modify org.nexa.nexad.plist if you intend to use it as a
Launch Daemon with a dedicated nexa user.

## Auto-respawn

Auto respawning is currently only configured for Upstart and systemd.
Reasonable defaults have been chosen but YMMV.
