"""
WakeOnPI by Andreas

Copyright Andreas B. 2025
"""


import json
import os
import socket
import struct
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

mac_cache = {}

def is_reachable(ip: str) -> bool:
    """Prüft, ob eine IP erreichbar ist (Ping)."""
    try:
        # ping: -c 1 = 1 Paket, -W 1 = Timeout 1 Sekunde (Linux/Mac)
        # Für Windows -> "-n 1 -w 1000"
        param = "-n" if os.name == "nt" else "-c"
        timeout = "-w" if os.name == "nt" else "-W"
        result = subprocess.run(
            ["ping", param, "1", timeout, "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except Exception:
        return False


def send_magic_packet(mac: str):
    """Sendet ein Wake-on-LAN Magic Packet."""
    mac_bytes = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    packet = b"\xff" * 6 + mac_bytes * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(packet, ("<broadcast>", 9))


# --- Webserver ---
class SimpleAPIHandler(BaseHTTPRequestHandler):
    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        path = parsed.path

        if path == "/ping":
            ip = params.get("ip", [None])[0]
            if not ip:
                self._send_json({"error": "Missing ?ip parameter"}, 400)
                return
            reachable = is_reachable(ip)
            self._send_json({"ip": ip, "reachable": reachable})
            return

        elif path == "/setmac":
            ip = params.get("ip", [None])[0]
            mac = params.get("mac", [None])[0]
            if not ip or not mac:
                self._send_json({"error": "Missing ?ip or ?mac parameter"}, 400)
                return
            mac_cache[ip] = mac
            self._send_json({"ip": ip, "mac": mac, "status": "stored"})
            return

        elif path == "/wake":
            ip = params.get("ip", [None])[0]
            if not ip:
                self._send_json({"error": "Missing ?ip parameter"}, 400)
                return
            mac = mac_cache.get(ip)
            if not mac:
                self._send_json({"error": f"No MAC cached for {ip}"}, 404)
                return
            try:
                send_magic_packet(mac)
                self._send_json({"ip": ip, "mac": mac, "status": "Magic packet sent"})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        elif path == "/cache":
            self._send_json({"cache": mac_cache})
            return

        else:
            self._send_json({"error": "Unknown endpoint"}, 404)


def run_server(host="0.0.0.0", port=8080):
    print(f"[*] Server läuft auf http://{host}:{port}")
    httpd = HTTPServer((host, port), SimpleAPIHandler)
    httpd.serve_forever()


if __name__ == "__main__":
    run_server()