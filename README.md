# WakeOnPI

Send WakeOnLAN (WOL) packages to any device in your local network using a Raspberry PI (or any other device beeing able to run a Python script). The device can be started/monitored via a simple web interface. 

To get started simply type 

```bash
# Create a local directory for the script and config
cd /opt

# Clone the repository
sudo git clone "https://github.com/andreasmz/wakeonpi"

cd /opt/wakeonpi
```

You can now start the webserver manually with
```bash
python /opt/wakeonpi/wakeonpi.py
```

```bash
WakeOnPI

options:
  -h, --help        show this help message and exit
  -host HOST        The address of the server. Can be an valid IPv4/IPv6 address or a (resolvable) domain
  -port PORT        Port of the server. Defaults to 80/443
  -key KEY          Specify a keyfile to use for the https server
  -cert CERT        Specify a certificate to use for the https server
  -key-pwd KEY_PWD  If the keyfile is encrypted, specify the password here
  -d domain         If not empty, only accept queries from this domain
  -upgrade          If given (and port NOT specified), upgrade http to https
```

Note: To run a https server, you need both a certificate and a private key.

It is recommened to run the server as a systemd service in the background. Thatway Linux will autostart the script, manage the log files and make sure only one instance runs at a time. Start with creating a `.service` file:

```bash
sudo touch /etc/systemd/sytem/wakeonpi.service
sudo nano /etc/systemd/system/wakeonpi.service
```

```ini
[Unit]
Description=WakeOnPI
After=network.target

[Service]
type=simple
ExecStart=python /opt/wakeonpi/wakeonpi.py [-host host] [-port port] -upgrade
Restart=on-failure
RestartSec=60
StandardOutput=append:/var/log/wakeonpi.log
StandardError=append:/var/log/wakeonpi.log

# Prevent multiple instances
PIDFile=/run/wakeonpi.pid

[Install]
WantedBy=multi-user.target
```

Finally, start the service
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
sudo git pull origin main

sudo systemctl restart wakeonpi.service
```