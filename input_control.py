# HaiveControl — LAN remote control & screen sharing with an AI/MCP interface.
# Copyright (C) 2026 The HaiveControl Authors.
# SPDX-License-Identifier: AGPL-3.0-or-later

from pynput.keyboard import Controller as KeyboardController, Key, KeyCode
from pynput.mouse import Button, Controller as MouseController

MOUSE_BUTTONS = {0: Button.left, 1: Button.middle, 2: Button.right}

SPECIAL_KEYS = {
    "Enter": Key.enter, "Backspace": Key.backspace, "Tab": Key.tab,
    "Escape": Key.esc, " ": Key.space, "Delete": Key.delete,
    "ArrowUp": Key.up, "ArrowDown": Key.down,
    "ArrowLeft": Key.left, "ArrowRight": Key.right,
    "Shift": Key.shift, "Control": Key.ctrl, "Alt": Key.alt, "Meta": Key.cmd,
    "CapsLock": Key.caps_lock, "Home": Key.home, "End": Key.end,
    "PageUp": Key.page_up, "PageDown": Key.page_down, "Insert": Key.insert,
    "F1": Key.f1, "F2": Key.f2, "F3": Key.f3, "F4": Key.f4,
    "F5": Key.f5, "F6": Key.f6, "F7": Key.f7, "F8": Key.f8,
    "F9": Key.f9, "F10": Key.f10, "F11": Key.f11, "F12": Key.f12,
}


class InputController:
    """Injects mouse and keyboard events. Browser sends normalized (0..1)
    coordinates; we map them onto the captured monitor's absolute geometry."""

    def __init__(self, geometry):
        self.geo = geometry
        self.mouse = MouseController()
        self.keyboard = KeyboardController()

    def _abs(self, nx, ny):
        x = self.geo["left"] + nx * self.geo["width"]
        y = self.geo["top"] + ny * self.geo["height"]
        return int(x), int(y)

    def handle(self, ev):
        kind = ev.get("type")
        if kind == "move":
            self.mouse.position = self._abs(ev["x"], ev["y"])
        elif kind == "down":
            self.mouse.position = self._abs(ev["x"], ev["y"])
            self.mouse.press(MOUSE_BUTTONS.get(ev.get("button", 0), Button.left))
        elif kind == "up":
            self.mouse.release(MOUSE_BUTTONS.get(ev.get("button", 0), Button.left))
        elif kind == "scroll":
            self.mouse.scroll(0, ev.get("dy", 0))
        elif kind == "key":
            self._key(ev)

    def _key(self, ev):
        key = self._resolve(ev.get("key", ""))
        if key is None:
            return
        if ev.get("action") == "down":
            self.keyboard.press(key)
        else:
            self.keyboard.release(key)

    def _resolve(self, key):
        if key in SPECIAL_KEYS:
            return SPECIAL_KEYS[key]
        if len(key) == 1:
            return KeyCode.from_char(key)
        return None
