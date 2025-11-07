"""
WakeOnPI by Andreas

Copyright Andreas B. 2025
"""

import argparse
import configparser
import ipaddress
import json
import logging
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import types
from dataclasses import dataclass
from http.server import  HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from threading import Thread
from typing import cast
from urllib.parse import urlparse, parse_qs, unquote
from uuid import uuid4

logger = logging.getLogger("WakeOnPI")
logger.setLevel(logging.DEBUG)
_fmt = logging.Formatter('[%(asctime)s %(levelname)s]: %(message)s')

stream_logging_handler = logging.StreamHandler(stream=sys.stdout)
stream_logging_handler.setFormatter(_fmt)
stream_logging_handler.setLevel(logging.DEBUG)
logger.addHandler(stream_logging_handler)

def log_exceptions_hook(exc_type: type[BaseException], exc_value: BaseException, exc_traceback: types.TracebackType | None = None) -> None:
    """ Internal function to log exceptions and not crash the server """
    global logger
    if isinstance(exc_type, KeyboardInterrupt):
        logger.info(f"Stopping WakeOnPI (Keyboard Interrupt)")
        exit()
        return
    logger.exception(f"{exc_type.__name__}:", exc_info=(exc_type, exc_value, exc_traceback))

sys.excepthook = log_exceptions_hook

parser = argparse.ArgumentParser(description="WakeOnPI")
parser.add_argument("-host", type=str, default="", help="The address of the server. Can be an valid IPv4/IPv6 address or a (resolvable) domain")
parser.add_argument("-port", type=int, default=-1, help="Port of the server")
parser.add_argument("-key", type=str, default="", help="Specify a keyfile to use for the https server")
parser.add_argument("-cert", type=str, default="", help="Specify a certificate to use for the https server")
parser.add_argument("-key-pwd", type=str, default="", help="If the keyfile is encrypted, specify the password here")
parser.add_argument("-d", type=str, default="", help="If not empty, only accept queries from this domain")
parser.add_argument("-upgrade", action="store_true",  help="If given (and port NOT given), upgrade http to https")

args = parser.parse_args()

def ping(ip: ipaddress.IPv4Address|ipaddress.IPv6Address, timeout: float = 2.0) -> bool:
    """ Returns if a given host is reachable via ping """
    param = '-n' if platform.system().lower().startswith('win') else '-c'
    cmd = ['ping', param, '1', '-w', str(timeout), str(ip)] if param == '-n' else ['ping', param, '1', '-W', timeout, host]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0


def get_mac(ip: ipaddress.IPv4Address|ipaddress.IPv6Address) -> str|None:
    """ Tries to query the mac adress from an given IP. Returns None if the host can not be found in the local network """
    ping(ip, timeout=1)
    system = platform.system().lower()
    cmd = ['arp', '-a', str(ip)] if system.startswith('win') else ['arp', '-n', str(ip)]
    try:
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, encoding="cp437")
    except Exception as ex:
        logger.error(f"Failed to query the MAC-address for {ip}: ", exc_info=True)
        return None
    if not (m := re.search(r'([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}', output)):
        logger.info(f"Failed to query the MAC for {ip}: The ARP table has no entry for the given host")
        return None 
    return m.group(0).replace("-", ":").upper()

def send_wol_package(broadcast_ip: ipaddress.IPv4Address|ipaddress.IPv6Address, mac: str, n: int = 3) -> bool:
    """ Send a WakeOnLAN package to the given MAC via the given broadcast IP n times """
    mac = mac.upper()
    if not re.match(r"([0-9A-F]{2}[:]){5}([0-9A-F]{2})", mac):
        raise ValueError(f"Invalid MAC '{mac}'")
    payload = b"\xff"*6 + bytes.fromhex(mac.replace(":", ""))*16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.settimeout(1.0)
        try:
            for i in range(n):
                s.sendto(payload, (str(broadcast_ip), 9))
        except Exception as ex:
            logger.error(f"Failed to send WOL package to {mac} via {broadcast_ip}: ", exc_info=True)
            return False
    logger.info(f"WOL package sent to {mac} via {broadcast_ip} ")
    return True


config = configparser.ConfigParser()
config.read_dict({"SERVER": {"broadcast_ip": ""}})
config.read("wakeonpi.config")

def save_config() -> None:
    """ Save the .config file """
    global config
    for u, c in clients.items():
        if f"device-{u}" not in config.sections():
            config.add_section(f"device-{u}")
        config.set(f"device-{u}", "name", c.name)
        config.set(f"device-{u}", "ip", str(c.ip))
        config.set(f"device-{u}", "mac", c.mac.upper() if c.mac is not None else "")
        config.set(f"device-{u}", "last_wol", c.last_wol)
        config.set(f"device-{u}", "last_online", c.last_online)

    config.set("SERVER", "broadcast_ip", str(broadcast_ip) if broadcast_ip is not None else "")

    for us in [s for s in config.sections() if cast(str, s).startswith("device-")]:
        u = cast(str, us).replace("device-", "")
        if u not in clients:
            config.remove_section(us)
        
    try:
        with open("wakeonpi.config", "w") as f:
            config.write(f)
    except Exception:
        logger.error(f"Failed to save the config:", exc_info=True)

host: str = args.host
port: int = args.port

@dataclass
class Client:
    name: str
    ip: ipaddress.IPv4Address|ipaddress.IPv6Address|None
    mac: str|None
    last_wol: str
    last_online: str
clients: dict[str, Client] = {}

def reload_config():
    global clients, broadcast_ip
    broadcast_ip_raw = config.get("SERVER", "broadcast_ip", fallback="")

    try:
        broadcast_ip = ipaddress.ip_address(broadcast_ip_raw)
    except ValueError:
        logger.error(f"Invalid broadcast address '{broadcast_ip_raw}'")
        broadcast_ip = None

    for us in [s for s in config.sections() if cast(str, s).startswith("device-")]:
        us: str
        try:
            ip = ipaddress.ip_address(config.get(us, "ip", fallback=""))
        except ValueError:
            logger.warning(f"Malformed IP for {us}")
            continue
        mac = config.get(us, "mac", fallback="")
        if not re.match(r"([0-9A-F]{2}[:\-]){5}[0-9A-Fa-f]{2}", config.get(us, "mac", fallback="").upper().replace("-", ":")):
            mac = get_mac(ip)
            if mac is not None:
                logger.info(f"Found MAC {mac} for {ip}")
                config.set(us, "mac", mac)
        clients[us.replace("device-", "")] = Client(config.get(us, "name", fallback=""), ip, mac, config.get(us, "last_wol", fallback=""), config.get(us, "last_online", fallback=""))
    logger.debug(f"Loaded {len(clients)} clients from config: {[', '.join([c.name for c in clients.values()])]}")

reload_config()
save_config()

class WakeOnPIServer(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        d = (Path(__file__) / "web").resolve()
        logger.info(f"Servig web server for directory '{d}'")
        super().__init__(*args, directory=d, **kwargs)

    def do_GET(self):
        global host, clients, broadcast_ip
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        path = parsed.path

        if args.d and not (d := self.headers.get("Host", "").lower()) == args.d.lower():
            logger.warning(f"Refused connection to host '{d}'")
            self.send_response(403)
            self.end_headers()
            self.wfile.write(f"403: Forbidden".encode("utf-8"))
            return
        
        c: Client|None = None
        uuid: str|None = None
        if "uuid" in params and len(params["uuid"]) >= 1 and params["uuid"][0] in clients:
            uuid = params["uuid"][0]
            c = clients[uuid]
        
        match path:
            case "/api/list":
                self._send_json({"status": True, "devices": {u: {"name": c.name, "ip": str(c.ip), "mac": c.mac, "last_online": c.last_online, "last_wol": c.last_wol} for u, c in clients.items()}}) 
            case "/api/ping":
                if c is None:
                    self._send_json({"status": False, "status_info": "Missing or malformed paramter 'uuid'"})
                    return
                if c.ip is None:
                    self._send_json({"status": False, "status_info": "Device has no valid IP"})
                    return
                r = ping(c.ip)
                logger.info(f"Pinged {c.ip}: {r}")
                self._send_json({"status": True, 
                                 "name": c.name, 
                                 "ip": str(c.ip), 
                                 "mac": c.mac if c.mac is not None else "", 
                                 "last_online": c.last_online, 
                                 "last_wol": c.last_wol, 
                                 "ping": r})
            case "/api/add":
                clients[(uuid := str(uuid4()))] = Client("", ipaddress.ip_address("127.0.0.1"), "", "", "")
                if "name" in params:
                    if len(params["name"]) != 1:
                        self._send_json({"status": False, "status_info": "Missing or malformed paramter 'name'"})
                        return
                    name = unquote(params["name"][0])
                    clients[uuid] .name = name
                save_config()
                reload_config()
                c = clients[uuid]
                logger.info(f"Added device {uuid} ('{c.name}')")
                self._send_json({"status": True, "device": {
                    uuid : {"name": c.name, 
                            "ip": str(c.ip), 
                            "mac": c.mac if c.mac is not None else "", 
                            "last_online": c.last_online, 
                            "last_wol": c.last_wol}}})
            case "/api/remove":
                if c is None:
                    self._send_json({"status": False, "status_info": "Missing or malformed paramter 'uuid'"})
                    return
                del clients[params["uuid"][0]]
                save_config()
                reload_config()
                logger.info(f"Removed device {uuid}")
                self._send_json({"status": True})
            case "/api/update":
                if c is None:
                    self._send_json({"status": False, "status_info": "Missing or malformed paramter 'uuid'"})
                    return
                if "name" in params:
                    if len(params["name"]) != 1:
                        self._send_json({"status": False, "status_info": "Missing or malformed paramter 'name'"})
                        return
                    name = unquote(params["name"][0])
                    logger.info(f"Updated client {uuid} name from '{c.name}' to '{name}'")
                    c.name = name
                if "mac" in params:
                    if len(params["mac"]) != 1:
                        self._send_json({"status": False, "status_info": "Missing or malformed paramter 'mac'"})
                        return
                    mac = params['mac'][0]
                    logger.info(f"Updated client {uuid} MAC from '{c.mac}' to '{mac}'")
                    c.mac = mac
                if "ip" in params:
                    if len(params["ip"]) != 1:
                        self._send_json({"status": False, "status_info": "Missing or malformed paramter 'ip'"})
                        return
                    try:
                        ip = ipaddress.ip_address(params["ip"][0])
                    except ValueError:
                        self._send_json({"status": False, "status_info": "Missing or malformed paramter 'ip'"})
                        return
                    logger.info(f"Updated client {uuid} IP from {c.ip} to {params['ip'][0]}")
                    c.ip = ip
                save_config()
                reload_config()
                self._send_json({"status": True})
            case "/api/wol":
                if c is None:
                    self._send_json({"status": False, "status_info": "Missing or malformed paramter 'uuid'"})
                    return
                if broadcast_ip is None:
                    self._send_json({"status": False, "status_info": "No broadcast-address has been specified"})
                    return
                if c.mac is None:
                    self._send_json({"status": False, "status_info": "Device is missing valid MAC-address"})
                    return
                r = send_wol_package(broadcast_ip, c.mac)
                logger.info(f"Pinged {c.ip}: {r}")
                self._send_json({"status": True, "name": c.name, "ip": str(c.ip), "mac": c.mac if c.mac is not None else "",  "last_online": c.last_online, "last_wol": c.last_wol, "ping": r})
            case _:
                super().do_GET()

    def guess_type(self, path):
        base_type = super().guess_type(path)
        if base_type == "text/html":
            return "text/html; charset=utf-8"
        return base_type

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        body = json.dumps(data, indent=2).encode("utf-8")
        self.wfile.write(body)
        self.wfile.flush()

class RedirectHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        host = self.headers.get('Host')
        if host:
            host = host.split(':')[0]
        new_url = f"https://{host}{self.path}"
        self.send_response(301)
        self.send_header('Location', new_url)
        self.end_headers()

if __name__ == "__main__":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_enabled = False
    if (key_path := args.key) != "" and (cert_path := args.cert):
        key_path = Path(key_path).resolve()
        cert_path = Path(cert_path).resolve()

        if not key_path.exists():
            logger.warning(f"Key file '{key_path}' does not exist")
        elif not cert_path.exists():
            logger.warning(f"Cert file '{cert_path}' does not exist")
        else:
            pwd = args.key_pwd if args.key_pwd != "" else None
            try:
                context.load_cert_chain(certfile=cert_path, keyfile=key_path, password=pwd)
                context.load_verify_locations(cert_path)
            except Exception as ex:
                logger.error(f"Failed to load the certification chain: ", exc_info=True)
                exit(code=0)
            logger.debug(f"Loaded cert '{cert_path.name}' with key '{key_path.name}'")
            ssl_enabled = True

    if port == -1:
        port = 443 if ssl_enabled else 80   
        if ssl_enabled and args.upgrade: 
            def _redirect_server():
                httpd = HTTPServer((host, 80), RedirectHandler)
                logger.info(f"Started redirecting server on http://{host}:{80}")
                httpd.serve_forever()
            Thread(target=_redirect_server, daemon=True).start()


    SimpleHTTPRequestHandler.extensions_map = {k: v + ';charset=UTF-8' for k, v in SimpleHTTPRequestHandler.extensions_map.items()}
    httpd = HTTPServer((host, port), WakeOnPIServer)
    if ssl_enabled:
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    logger.info(f"Started server on http{'s' if ssl_enabled else ''}://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info(f"Stopping WakeOnPI (Keyboard Interrupt)")
        exit(code=0)