from __future__ import annotations

import sys
from mitmproxy.tools import main as mitmproxy_main

from app.config import PROXY_HOST, PROXY_PORT


def run_proxy():
    sys.argv = [
        "mitmproxy",
        "--mode",
        "regular",
        "--listen-host",
        PROXY_HOST,
        "--listen-port",
        str(PROXY_PORT),
        "--set",
        "block_global=false",
        "--set",
        "confdir=~/.mitmproxy",
        "--scripts",
        "app/llm_request_guard.py",
    ]

    print(f"Starting mitmproxy on {PROXY_HOST}:{PROXY_PORT}")
    print()

    mitmproxy_main.mitmdump()


if __name__ == "__main__":
    run_proxy()
