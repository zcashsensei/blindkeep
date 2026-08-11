"""Desktop launcher for the Blindkeep app.

.pyw so Windows runs it with pythonw and no console window appears.

Double-clicking twice must not break anything, so this checks whether the
dashboard is already serving before starting another one -- a second process
would fail on the bound port and leave a dead icon click with no explanation.
If it is already up, the browser is simply pointed at it.
"""
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

HERE = Path(__file__).resolve().parent
PORT = 8743
URL = f"http://127.0.0.1:{PORT}"


def already_running() -> bool:
    try:
        with urllib.request.urlopen(f"{URL}/", timeout=1.5) as r:
            return r.status == 200
    except (urllib.error.URLError, OSError):
        return False


def main() -> int:
    if not already_running():
        pyw = Path(sys.executable).with_name("pythonw.exe")
        exe = str(pyw) if pyw.exists() else sys.executable
        creation = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        subprocess.Popen([exe, str(HERE / "app.py")],
                         cwd=str(HERE), creationflags=creation,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Wait for it to bind rather than opening a browser at a dead port.
        for _ in range(40):
            if already_running():
                break
            time.sleep(0.25)
    webbrowser.open(URL)
    return 0


if __name__ == "__main__":
    sys.exit(main())
