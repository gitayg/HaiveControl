# HaiveControl — LAN remote control & screen sharing with an AI/MCP interface.
# Copyright (C) 2026 The HaiveControl Authors.
# SPDX-License-Identifier: AGPL-3.0-or-later

import socket

from zeroconf import ServiceInfo, Zeroconf

HUB_SERVICE = "_rmtscrn._tcp.local."


def local_ip():
    """Best-effort primary LAN IP (no traffic actually sent)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def advertise_hub(mac_id, port):
    """(Mac side) Publish the hub over Bonjour under instance name `mac_id`,
    so a Windows agent given only that id can find this Mac's IP + port.
    Returns (Zeroconf, ip) — keep the handle so it stays registered."""
    ip = local_ip()
    info = ServiceInfo(
        HUB_SERVICE,
        f"{mac_id}.{HUB_SERVICE}",
        addresses=[socket.inet_aton(ip)],
        port=port,
        server=f"{mac_id}-hub.local.",
    )
    zc = Zeroconf()
    zc.register_service(info)
    return zc, ip


def resolve_hub(mac_id, timeout=5.0):
    """(Windows side) Resolve a hub by its id → (ip, port), or None."""
    zc = Zeroconf()
    try:
        info = zc.get_service_info(
            HUB_SERVICE, f"{mac_id}.{HUB_SERVICE}", timeout=int(timeout * 1000)
        )
        if not info or not info.addresses:
            return None
        return socket.inet_ntoa(info.addresses[0]), info.port
    finally:
        zc.close()
