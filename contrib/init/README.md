Sample configuration files for:

SystemD: nexad.service
Upstart: nexad.conf
OpenRC:  nexad.openrc
         nexad.openrcconf
CentOS:  nexad.init
OS X:    org.nexa.nexad.plist

have been made available to assist packagers in creating node packages here.

See doc/init.md for more information.


## Systemd (ubuntu)

Choose whether you want to run just the full node or both the full node and the miner and follow the steps in the sections below.  

THEN reconfigure and start the services as follows:
```
sudo systemctl daemon-reload
sudo service nexa start
sudo service nexa-miner start
```

Next verify that its all working.  For example use ```ps -efww | grep nexa``` to see if processes are running.  Or use ```journalctl -xeu nexa``` or ```journalctl -xeu nexa-miner`` to see the output of these services.  

When it all looks good, you can enable the services to auto-start on reboot via:

```
sudo systemctl enable nexa
sudo systemctl enable nexa-miner
```

### Full node

 * edit nexa.service and change User= and Group= to your username (current the user/group "nexa" is chosen)
 * change every instance of /home/nexa to /home/<your username>
 
 * copy this file to /etc/systemd/system/nexa.service on the target machine
 
### Miner

 * edit nexa-miner.service and change User= and Group= to your username (current the user/group "nexa" is chosen)
 * change every instance of /home/nexa to /home/<your username>
 
 * copy this file to /etc/systemd/system/nexa-miner.service on the target machine


