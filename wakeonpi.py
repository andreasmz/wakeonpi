"""
WakeOnPI by Andreas

Copyright Andreas B. 2025
"""

import configparser
import json
import logging
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger("WakeOnPI")
_fmt = logging.Formatter('[%(asctime)s %(levelname)s]: %(message)s')

stream_logging_handler = logging.StreamHandler(stream=sys.stdout)
stream_logging_handler.setFormatter(_fmt)
stream_logging_handler.setLevel(logging.DEBUG)

def log_exceptions_hook(exc_type: type[BaseException], exc_value: BaseException, exc_traceback: types.TracebackType | None = None) -> None:
    global logger
    logger.exception(f"{exc_type.__name__}:", exc_info=(exc_type, exc_value, exc_traceback))
    sys.__excepthook__(exc_type, exc_value, exc_traceback)

sys.excepthook = log_exceptions_hook

config = configparser.ConfigParser(defaults={"host": "127.0.0.1", "port": 80})
config.read("wakeonpi.config")

def save_settings() -> None:
    global config
    try:
        with open("wakeonpi.config", "w") as f:
            config.write(f)
    except Exception:
        logger.error(f"Failed to save the config:", exc_info=True)

save_settings()

host = config.get("host")
port = config.getint("DEFAULT")
if port <= 0 or port > 65535:
    raise Exception(f"Invalid port '{port}'")


class WakeOnPIServer(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        path = parsed.path

        logger.debug(f"GET '{self.path}'")

        if path == "/api/ping": # /api/ping?ip=127.0.0.1
            ip = params.get("ip", [None])[0]
            if not ip:
                self._send_json({"error": "Invalid ip"}, 400)
                return
            

        else:
            self._send_json({"error": "Unknown endpoint"}, 404)

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))



if __name__ == "__main__":
    httpd = HTTPServer((host, port), WakeOnPIServer)
    logger.info(f"Started server on http://{host}:{port}")
    httpd.serve_forever()