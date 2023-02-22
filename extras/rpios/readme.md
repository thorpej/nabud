# Raspberry Pi OS instructions

This is a systemd service unit to allow systemd to start, stop and restart the nabud daemon. It is configured to run under the user nabu and outputs the log to /var/log/nabud. The service requires that wifi is configured properly on the Raspberry Pi as nabud will not start until wifi has an ip.

Create user nabu and add them to the dialer group with these commands:
```
sudo useradd nabu
sudo usermod -G dialer nabu
```

Edit nabud.service to have the correct location of the nabud binary in the ExecStart entry

Make sure all files used for the channel feed and storage are owned by the user nabu. I use /home/nabu as my base so I run the following:
`sudo chown -R nabu:nabu /home/nabu/`

Place the file nabud.service in /lib/systemd/system and run the following commands to enable the nabud service:
```
sudo systemctl daemon-reload
sudo systemctl enable nabud.service
```

Nabud will now start once the Raspberry Pi is rebooted or can be started with the following command:
`sudo systemctl start nabud.service`
