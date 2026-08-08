#!/usr/bin/env python3
"""Install the repository's git hooks.

`.git/hooks` is not version-controlled, so the hook has to be copied in. Run
this once per clone:

    py -3 tools/install_hooks.py
"""

from __future__ import annotations

import shutil
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "tools" / "hooks"
TARGET = ROOT / ".git" / "hooks"


def main() -> int:
    if not TARGET.is_dir():
        print(f"no .git/hooks at {TARGET} -- is this a git clone?", file=sys.stderr)
        return 1

    for src in sorted(SOURCE.iterdir()):
        if not src.is_file():
            continue
        dst = TARGET / src.name
        shutil.copyfile(src, dst)
        dst.chmod(dst.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        print(f"installed {dst.relative_to(ROOT).as_posix()}")

    print("\nVerify with: py -3 tools/check_counts.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
