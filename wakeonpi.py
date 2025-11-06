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
from http.server import  HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import cast, NamedTuple
from urllib.parse import urlparse, parse_qs
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
parser.add_argument("host", type=str, default="127.0.0.1", help="The address of the server. Can be an valid IPv4/IPv6 address or a (resolvable) domain")
parser.add_argument("port", type=int, default=80, help="Port of the server")
parser.add_argument("-key", type=str, default="", help="Specify a keyfile to use for the https server")
parser.add_argument("-cert", type=str, default="", help="Specify a certificate to use for the https server")
parser.add_argument("-key-pwd", type=str, default="", help="If the keyfile is encrypted, specify the password here")

def ping(ip: ipaddress.IPv4Address|ipaddress.IPv6Address, timeout: float = 2.0) -> bool:
    """ Returns if a given host is reachable via ping """
    param = '-n' if platform.system().lower().startswith('win') else '-c'
    cmd = ['ping', param, '1', '-w', str(timeout), ip] if param == '-n' else ['ping', param, '1', '-W', timeout, host]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0


def get_mac(ip: ipaddress.IPv4Address|ipaddress.IPv6Address) -> str|None:
    """ Tries to query the mac adress from an given IP. Returns None if the host can not be found in the local network """
    ping(ip, timeout=1)
    system = platform.system().lower()
    cmd = ['arp', '-a', ip] if system.startswith('win') else ['arp', '-n', ip]
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
                s.sendto(payload, (broadcast_ip, 9))
        except Exception as ex:
            logger.error(f"Failed to send WOL package to {mac} via {broadcast_ip}: ", exc_info=True)
            return False
    logger.info(f"WOL package sent to {mac} via {broadcast_ip} ")
    return True


config = configparser.ConfigParser()
config.read("wakeonpi.config")

def save_settings() -> None:
    """ Save the .config file """
    global config
    try:
        with open("wakeonpi.config", "w") as f:
            config.write(f)
    except Exception:
        logger.error(f"Failed to save the config:", exc_info=True)

host = config.get("SERVER", "host", fallback="")
broadcast_ip_raw = config.get("SERVER", "broadcast_ip", fallback="")
port = config.getint("SERVER", "port", fallback=0)

try:
    broadcast_ip = ipaddress.ip_address(broadcast_ip_raw)
except ValueError:
    logger.error(f"Invalid broadcast address '{broadcast_ip_raw}'. Terminating")
    exit()

Client = NamedTuple("Client", [("name", str), ("ip", ipaddress.IPv4Address|ipaddress.IPv6Address), ("mac", str|None)])
clients: dict[str, Client] = {}

def reload_devices():
    global clients
    for u in [s for s in config.sections() if cast(str, s).startswith("client-")]:
        try:
            ip = ipaddress.ip_address(config.get(u, "ip", fallback=""))
        except ValueError:
            logger.warning(f"Malformed IP for device {u}")
            continue
        mac = config.get(u, "mac", fallback="")
        if not re.match(r"([0-9A-F]{2}[:\-]){5}[0-9A-Fa-f]{2}", config.get(u, "mac", fallback="").upper().replace("-", ":")):
            mac = get_mac(ip)
            if mac is not None:
                logger.info(f"Found MAC {mac} for {ip}")
                config.set(u, "mac", mac)
        clients[u] = Client(config.get(u, "name", fallback=""), ip, mac)
    logger.debug(f"Loaded {len(clients)} from config: {[', '.join([c.name for c in clients.values()])]}")

reload_devices()
save_settings()


class WakeOnPIServer(SimpleHTTPRequestHandler):
    def do_GET(self):
        global host, clients, broadcast_ip
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        path = parsed.path

        if not (d := self.headers.get("Host", "")) == host:
            logger.warning(f"Refused connection to host '{d}'")
            self.send_response(403)
            self.end_headers()
            self.wfile.write(f"403: Forbidden".encode("utf-8"))
            return
        
        c: Client|None = None
        if "uuid" in params and len(params["uuid"]) >= 1 and params["uuid"][0] in clients:
            c = clients[params["uuid"][0]]
        
        match path:
            case "/api/get_clients":
                self._send_json({c for c in clients}) 
            case "/api/ping":
                if c is None:
                    self._send_json({"status": False, "status_info": "Missing or malformed paramter 'uuid'"})
                    return
                r = ping(c.ip)
                logger.info(f"Pinged {c.ip}: {r}")
                self._send_json({"name": c.name, "ip": c.ip, "mac": c.mac, "ping": r})
            case "/api/wol":
                if c is None:
                    self._send_json({"status": False, "status_info": "Missing or malformed paramter 'uuid'"})
                    return
                if c.mac is None:
                    self._send_json({"status": False, "status_info": "Device is missing valid MAC-address"})
                    return
                r = send_wol_package(broadcast_ip, c.mac)
                logger.info(f"Pinged {c.ip}: {r}")
                self._send_json({"name": c.name, "ip": c.ip, "mac": c.mac, "ping": r})
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

if __name__ == "__main__":
    os.chdir((d := Path("web").resolve()))
    SimpleHTTPRequestHandler.extensions_map = {k: v + ';charset=UTF-8' for k, v in SimpleHTTPRequestHandler.extensions_map.items()}
    httpd = HTTPServer((host, port), WakeOnPIServer)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_enabled = False
    if (cert_path := Path("../WakeOnPI.cer")).exists() and (key_path := Path("../WakeOnPI_encrypted.key")).exists():
        context.load_cert_chain(certfile=cert_path, keyfile=key_path, password=input("SSL Passwort: "))
        context.load_verify_locations(cert_path)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        logger.info(f"Loaded ssl certificate from disk")
        ssl_enabled = True

    logger.info(f"Started server on http{'s' if ssl_enabled else ''}://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info(f"Stopping WakeOnPI (Keyboard Interrupt)")