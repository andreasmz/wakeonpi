# WakeOnPI

Send WakeOnLAN (WOL) packages to any device in your local network using a Raspberry PI (or any other device beeing able to run a Python script). The device can be started/monitored via a simple web interface. 

To get started simply type 

```bash
# Create a local directory for the script and config
mkdir /opt/wakeonpi 
cd /opt/wakeonpi

# Clone the repository
git clone "https://github.com/andreasmz/wakeonpi"
```

You should now edit the wakeonpi.config file and specify at least the server host and port.
If you specify a domain, the webinterface will only response to requests on this domain and
answer all other querys with 403 Forbidden (Note: This will block querys using IP adresses
as well).

```bash
nano /opt/wakeonpi/wakeonpi.config
```

You can now start the webserver manually with
```bash
python /opt/wakeonpi/wakeonpi.py
```

or make it a systemd service to autostart it by creating a `.service` file 
```bash
sudo nano /etc/system/system/wakeonpi.service
```
```ini
[Unit]
Description=WakeOnPI
After=network.target

[Service]
type=simple
ExecStart=python /opt/wakeonpi/wakeonpi.config
Restart=on-failure
RestartSec=60
StandardOutput=append:/var/log/wakeonpi.log
StandardError=append:/var/log/wakeonpi.log

# Prevent multiple instances
PIDFile=/run/wakeonpi.pid

[Install]
WantedBy=multi-user.target
```

Now startt the service
```bash
sudo systemctl daemon-reload
sudo systemctl enable wakeonpi.service
sudo systemctl start wakeonpi.service
```

and verify the script is running

```bash
sudo systemctl status wakeonpi.service
```

### Troubleshooting

##### Python not found

In case you get the error `bash: python: command not found` you need to install Python first

```bash
# First update the system
sudo apt update
sudo apt upgrade

# Now install Python
sudo apt install python3

# Verify Python is installed
python --version
```

##### Updating

```bash
cd /opt/wakeonpi
git pull origin master
```