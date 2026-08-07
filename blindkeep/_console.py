"""Console encoding for the command-line entry points.

Windows hands a redirected or piped process a cp1252 stdout, and cp1252 cannot
encode the characters the status output is built from -- ``progress`` alone uses
U+2713 CHECK MARK and U+2192 RIGHTWARDS ARROW. Printing one raises
UnicodeEncodeError, so ``blindkeep progress > file`` exited 1 having written none
of its 22 detector lines, while the same command in a terminal printed all 22.

That failure mode is worse than a crash. A status command reports nothing exactly
when something is collecting its output -- a CI step, a supervisor, a dashboard
refresh -- and an empty report reads like a clean board rather than a broken one.
The terminal, where a human would have noticed, is the one place it worked.

Called from each ``main()`` rather than at import time: the package is
pip-installable, and a library must not reconfigure the streams of a program that
merely imports it.
"""

from __future__ import annotations

import sys


def use_utf8_stdout() -> None:
    """Make stdout and stderr able to carry any character we print.

    Best-effort by design. Under the test harness these streams are often a plain
    ``StringIO`` with no ``reconfigure`` at all, and a captured stream is already
    Unicode-safe, so failing to reconfigure one is not an error worth raising.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError, OSError):
            pass
