from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

try:
    from .config import PROXY_HOST, PROXY_PORT, get_proxy_auth_spec
except ImportError:
    try:
        from app.config import PROXY_HOST, PROXY_PORT, get_proxy_auth_spec
    except ImportError:
        config_spec = importlib.util.spec_from_file_location(
            "proxy_local_config",
            Path(__file__).with_name("config.py"),
        )
        if config_spec is None or config_spec.loader is None:
            raise ImportError("Could not load proxy config module")
        proxy_config = importlib.util.module_from_spec(config_spec)
        config_spec.loader.exec_module(proxy_config)
        PROXY_HOST = proxy_config.PROXY_HOST
        PROXY_PORT = proxy_config.PROXY_PORT
        get_proxy_auth_spec = proxy_config.get_proxy_auth_spec


def build_mitmdump_argv() -> list[str]:
    argv = [
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

    proxy_auth = get_proxy_auth_spec()
    if proxy_auth:
        argv.extend(["--proxyauth", proxy_auth])

    return argv


def run_proxy():
    from mitmproxy.tools import main as mitmproxy_main

    sys.argv = build_mitmdump_argv()

    print(f"Starting mitmproxy on {PROXY_HOST}:{PROXY_PORT}")
    if "--proxyauth" in sys.argv:
        print("Proxy client authentication enabled")
    print()

    mitmproxy_main.mitmdump()


if __name__ == "__main__":
    run_proxy()
