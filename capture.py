# HaiveControl — LAN remote control & screen sharing with an AI/MCP interface.
# Copyright (C) 2026 The HaiveControl Authors.
# SPDX-License-Identifier: AGPL-3.0-or-later

import io

import mss
from PIL import Image


class ScreenGrabber:
    """Grabs the screen and returns JPEG bytes. `monitor` follows mss indexing:
    0 = all monitors stitched into one virtual screen, 1 = primary, 2 = second, ..."""

    def __init__(self, monitor=0):
        self.monitor_index = monitor

    def grab_jpeg(self, sct, quality=60, max_width=1600):
        mon = sct.monitors[self.monitor_index]
        raw = sct.grab(mon)
        img = Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")
        if max_width and img.width > max_width:
            height = round(img.height * max_width / img.width)
            img = img.resize((max_width, height), Image.BILINEAR)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=quality)
        return buf.getvalue()
