"""Terminal styling and an arrow-key menu. Stdlib only; Windows and POSIX.

Keys come from msvcrt on Windows and termios elsewhere. When input or output
is not a real terminal, the menu falls back to numbered prompts.
"""

from __future__ import annotations

import os
import shutil
import sys
from typing import List, Optional, Sequence, TextIO


def _enable_windows_vt() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32  # type: ignore[attr-defined]
        ok = False
        for handle in (-11, -12):
            h = k.GetStdHandle(handle)
            mode = ctypes.c_uint32()
            if k.GetConsoleMode(h, ctypes.byref(mode)):
                ok = bool(k.SetConsoleMode(h, mode.value | 0x0004)) or ok
        return ok
    except Exception:
        return False


class Term:
    def __init__(self, stream: Optional[TextIO] = None, color: Optional[bool] = None):
        self.out = stream or sys.stdout
        try:
            tty = self.out.isatty()
        except (AttributeError, ValueError):
            tty = False
        self.tty = tty
        self.vt = tty and _enable_windows_vt()
        if color is None:
            color = tty and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"
        self.color = bool(color) and (self.vt or not tty)
        try:
            "│─█░✓›…·".encode(getattr(self.out, "encoding", None) or "ascii")
            self.uni = True
        except (UnicodeEncodeError, LookupError):
            self.uni = False

    @property
    def width(self) -> int:
        return max(60, min(110, shutil.get_terminal_size((100, 24)).columns))

    def g(self, fancy: str, plain: str) -> str:
        return fancy if self.uni else plain

    def c(self, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if self.color else s

    def bold(self, s: str) -> str: return self.c("1", s)
    def dim(self, s: str) -> str: return self.c("2", s)
    def red(self, s: str) -> str: return self.c("31", s)
    def green(self, s: str) -> str: return self.c("32", s)
    def yellow(self, s: str) -> str: return self.c("33", s)
    def cyan(self, s: str) -> str: return self.c("36", s)
    def magenta(self, s: str) -> str: return self.c("35", s)

    def say(self, s: str = "") -> None:
        print(s, file=self.out, flush=True)

    def err(self, s: str) -> None:
        print(self.red("error: ") + s, file=sys.stderr, flush=True)

    def warn(self, s: str) -> None:
        print(self.yellow("warning: ") + s, file=sys.stderr, flush=True)


# ---- keys -------------------------------------------------------------------

UP, DOWN, ENTER, ESC = "up", "down", "enter", "esc"


class Aborted(KeyboardInterrupt):
    pass


if os.name == "nt":
    import msvcrt

    def _read_key() -> str:
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            return {"H": UP, "P": DOWN}.get(msvcrt.getwch(), "")
        return _plain(ch)

    class _Raw:
        def __enter__(self): return self
        def __exit__(self, *a): return False
else:
    import termios
    import tty as _tty

    class _Raw:
        def __enter__(self):
            self.fd = sys.stdin.fileno()
            self.old = termios.tcgetattr(self.fd)
            _tty.setcbreak(self.fd)
            attrs = termios.tcgetattr(self.fd)
            attrs[3] &= ~termios.ISIG                 # Ctrl-C arrives as \x03 so we restore cleanly
            termios.tcsetattr(self.fd, termios.TCSANOW, attrs)
            return self

        def __exit__(self, *a):
            termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old)
            return False

    def _getc() -> str:
        return os.read(sys.stdin.fileno(), 1).decode("utf-8", "replace")

    def _read_key() -> str:
        ch = _getc()
        if ch != "\x1b":
            return _plain(ch)
        import select
        if not select.select([sys.stdin], [], [], 0.05)[0]:
            return ESC
        if _getc() not in ("[", "O"):
            return ESC
        seq = _getc()
        while seq.isdigit():                          # swallow e.g. ESC[5~
            seq = _getc()
        return {"A": UP, "B": DOWN}.get(seq, "")


def _plain(ch: str) -> str:
    if ch in ("\r", "\n"):
        return ENTER
    if ch == "\x1b":
        return ESC
    if ch == "\x03":
        raise Aborted()
    if ch == "\x04":
        raise EOFError()
    return ch


def menu_available(term: Term) -> bool:
    if os.environ.get("HEXSENTRY_NO_MENU"):
        return False
    try:
        return sys.stdin.isatty() and term.tty and term.vt and os.environ.get("TERM") != "dumb"
    except (AttributeError, ValueError):
        return False


def select(term: Term, title: str, options: Sequence[str], hints: Optional[Sequence[str]] = None,
           default: int = 0) -> Optional[int]:
    """Arrow keys / j k / number keys, Enter to pick, Esc or q to go back. Returns index or None."""
    hints = list(hints or [""] * len(options))
    if not menu_available(term):
        term.say(term.bold(title))
        for i, o in enumerate(options, 1):
            term.say(f"  {i}) {o}" + (term.dim(f"  {hints[i - 1]}") if hints[i - 1] else ""))
        while True:
            try:
                raw = input(f"choose 1-{len(options)} [{default + 1}]: ").strip()
            except EOFError:
                return None
            if not raw:
                return default
            if raw.lower() in ("q", "quit", "exit"):
                return None
            if raw.isdigit() and 1 <= int(raw) <= len(options):
                return int(raw) - 1

    idx = default
    lines = 1 + len(options) + 1
    out = term.out

    def draw(first: bool) -> None:
        if not first:
            out.write(f"\033[{lines}A")
        out.write("\r\033[2K" + term.bold(title) + "\n")
        for i, o in enumerate(options):
            sel = i == idx
            mark = term.cyan(term.g("›", ">")) if sel else " "
            text = term.bold(o) if sel else o
            hint = f"  {term.dim(hints[i])}" if hints[i] else ""
            out.write("\r\033[2K" + f" {mark} {text}{hint}" + "\n")
        out.write("\r\033[2K" + term.dim("  ↑/↓ move · enter select · esc back" if term.uni
                                           else "  up/down move, enter select, esc back") + "\n")
        out.flush()

    out.write("\033[?25l")
    try:
        draw(True)
        with _Raw():
            while True:
                k = _read_key()
                if k in (UP, "k"):
                    idx = (idx - 1) % len(options)
                elif k in (DOWN, "j"):
                    idx = (idx + 1) % len(options)
                elif k == ENTER:
                    return idx
                elif k in (ESC, "q"):
                    return None
                elif k.isdigit() and 1 <= int(k) <= len(options):
                    idx = int(k) - 1
                    draw(False)
                    return idx
                draw(False)
    finally:
        out.write("\033[?25h")
        out.flush()


def ask(term: Term, prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        v = input(f"{term.bold(prompt)}{term.dim(suffix)}: ").strip().strip('"').strip("'")
    except EOFError:
        return default
    return v or default


def confirm(term: Term, prompt: str, default: bool = True) -> bool:
    v = ask(term, prompt + (" (Y/n)" if default else " (y/N)")).lower()
    return default if not v else v.startswith("y")


def wrap(text: str, width: int, indent: str) -> List[str]:
    import textwrap
    return textwrap.wrap(text, width=max(30, width - len(indent)), initial_indent=indent,
                         subsequent_indent=indent, break_on_hyphens=False) or [indent]
