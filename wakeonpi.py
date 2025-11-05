"""
WakeOnPI by Andreas

Copyright Andreas B. 2025
"""

import configparser
import json
import logging
import platform
import re
import socket
import subprocess
import sys
import types
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger("WakeOnPI")
logger.setLevel(logging.DEBUG)
_fmt = logging.Formatter('[%(asctime)s %(levelname)s]: %(message)s')

stream_logging_handler = logging.StreamHandler(stream=sys.stdout)
stream_logging_handler.setFormatter(_fmt)
stream_logging_handler.setLevel(logging.DEBUG)
logger.addHandler(stream_logging_handler)

def log_exceptions_hook(exc_type: type[BaseException], exc_value: BaseException, exc_traceback: types.TracebackType | None = None) -> None:
    global logger
    if isinstance(exc_type, KeyboardInterrupt):
        logger.info(f"Stopping WakeOnPI (Keyboard Interrupt)")
        exit()
        return
    logger.exception(f"{exc_type.__name__}:", exc_info=(exc_type, exc_value, exc_traceback))

sys.excepthook = log_exceptions_hook

config = configparser.ConfigParser()
config.read_dict({"SERVER": {"host": "", "port": ""}, "CACHE": {"ip": "", "mac": ""}})
config.read("wakeonpi.config")

def save_settings() -> None:
    global config
    try:
        with open("wakeonpi.config", "w") as f:
            config.write(f)
    except Exception:
        logger.error(f"Failed to save the config:", exc_info=True)

save_settings()

# Functions

def ping(ip: str, timeout: float = 2.0) -> bool:
    """ Returns if a given host is reachable via ping """
    param = '-n' if platform.system().lower().startswith('win') else '-c'
    cmd = ['ping', param, '1', '-w', str(timeout), ip] if param == '-n' else ['ping', param, '1', '-W', str(timeout), host]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0


def get_mac(ip: str) -> None|str:
    """ Tries to query the mac adress from an given IP. Returns None if the host can not be found in the local network """
    ping(ip, timeout=1)
    system = platform.system().lower()
    cmd = ['arp', '-a', ip] if system.startswith('win') else ['arp', '-n', ip]
    try:
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, encoding="cp437")
    except Exception as ex:
        logger.error(f"An error happend when trying to retreive the MAC for '{ip}'", exc_info=True)
        return None
    if not (m := re.search(r'([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}', output)):
        logger.info(f"Failed to query the MAC for '{ip}': The ARP table has no entry for the given host")
        return None 
    return m.group(0).replace("-", ":").upper()

def send_wol_package(ip: str, mac: str, udp_port: int = 9, n: int = 3) -> bool:
    mac = mac.upper()
    if not re.match(r"([0-9A-F]{2}[:]){5}([0-9A-F]{2})", mac):
        raise ValueError(f"Invalid MAC '{mac}'")
    payload = b"\xff"*6 + bytes.fromhex(mac.replace(":", ""))*16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.settimeout(1.0)
        try:
            for i in range(n):
                s.sendto(payload, (ip, 9))
        except Exception as ex:
            logger.error(f"Failed to send WOL package to {ip}:{udp_port} ({mac}): ", exc_info=True)
            return False
    logger.info(f"WOL package sent to {ip}:{udp_port} ({mac})")
    return True

host = config.get("SERVER", "host")
try:
    port = config.getint("SERVER", "port")
except ValueError:
    logger.error(f"Invalid not integer port for server. Terminating")
    exit()
if port <= 0 or port > 65535:
    logger.error(f"Invalid port '{port}' for server. Terminating")
    exit()

mac = None
ip = None

def reload_cache():
    global ip, mac
    logger.debug(f"Loading values from the config")
    ip = config.get("CACHE", "ip")
    if ip == "":
        ip = None
    mac = config.get("CACHE", "mac")
    if not re.match(r'([0-9A-F]{2}[:]){5}[0-9A-F]{2}', mac):
        mac = None
    logger.debug(f"Loaded ip '{ip}' and mac '{mac}' from cache")

reload_cache()

if mac is None and ip is not None:
    mac = get_mac(ip)
    if mac is not None:
        logger.info(f"Found MAC '{mac}' for IP '{ip}'. Updating cache")
        config.set("CACHE", "mac", mac)
        save_settings()
        reload_cache()


class WakeOnPIServer(BaseHTTPRequestHandler):
    def do_GET(self):
        global ip, mac
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        path = parsed.path

        if path == "/api/ping":
            ping_result = False
            if ip is not None:
                ping_result = ping(ip)
                if not mac:
                    mac = get_mac(ip)
            logger.info(f"Pinged {ip}: {ping_result}")
            self._send_json({"ip": ip, "mac": mac, "ping": ping_result})
        elif path == "/api/set_ip": 
            if not "ip" in params:
                self._send_json({"status": False, "status_info": "Missing paramter 'ip'"})
                return
            elif len(params["ip"]) != 1:
                self._send_json({"status": False, "status_info": f"Malformed value for parameter 'ip': '{params['ip']}'"})
                return
            ip = params["ip"][0]
            config.set("CACHE", "ip", ip)
            logger.info(f"Updating IP to '{ip}'")
            save_settings()
            reload_cache()
            self._send_json({"status": True, "status_info": f"Updated ip to '{ip}'"})
        elif path == "/api/set_mac": 
            if not "mac" in params:
                self._send_json({"status": False, "status_info": "Missing paramter 'mac'"})
                return
            elif len(params["mac"]) != 1:
                self._send_json({"status": False, "status_info": f"Malformed value for parameter 'mac': '{params['mac']}'"})
                return
            mac = params["mac"][0]
            config.set("CACHE", "mac", mac)
            logger.info(f"Updating MAC to '{mac}'")
            save_settings()
            reload_cache()
            self._send_json({"status": True, "status_info": f"Updated MAC to '{mac}'"})
        elif path == "/api/wol":
            if ip is None:
                self._send_json({"wol": False, "wol_info": "No IP endpoint has been set yet"})
                return
            if mac is None:
                mac = get_mac(host)
            if mac is None:
                self._send_json({"wol": False, "wol_info": "Could not resolve the local MAC address"})
                return
            if not send_wol_package(ip, mac):
                self._send_json({"wol": False, "wol_info": "Failed to send WOL package"})
            else:
                self._send_json({"wol": True, "wol_info": ""})
        elif path == "/favicon.ico":
            self.send_response(404)
            self.end_headers()
            self.wfile.write("404 not found".encode("utf-8"))
        else:
            logger.info(f"Unknown endpoint '{}'")
            self._send_json({"error": "Unknown endpoint"}, 404)

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))



if __name__ == "__main__":
    httpd = HTTPServer((host, port), WakeOnPIServer)
    logger.info(f"Started server on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info(f"Stopping WakeOnPI (Keyboard Interrupt)")