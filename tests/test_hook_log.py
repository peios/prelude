"""Check the sourced hook logger without invoking boot or kernel operations."""

import os
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "src/hook-log.sh"


class HookLogTests(unittest.TestCase):
    """Messages stay literal and status output retains its stream and layout."""

    def test_literal_messages_with_and_without_color(self) -> None:
        cases = (
            ("log", "      ", "", False),
            ("log_ok", "  OK  ", "1;32", False),
            ("log_skip", " SKIP ", "1;33", False),
            ("log_warn", " WARN ", "1;33", True),
            ("log_fail", "FAILED", "1;31", True),
        )
        # Shells treat these differently under printf %b, including truncating
        # at \c. No message or component input may become a format string.
        component = r"disk\c%name"
        message = r"file\cafter \n \033[31m 100% %s"
        for color in ("0", "1"):
            for function, tag, sgr, stderr in cases:
                with self.subTest(color=color, function=function):
                    result = subprocess.run(
                        [
                            os.environ.get("TEST_SHELL", "/bin/sh"),
                            "-c",
                            '. "$1"; HOOK_LOG_COLOUR=$2; HOOK_LOG_COMPONENT=$3; "$4" "$5"',
                            "test-hook-log",
                            str(HELPER),
                            color,
                            component,
                            function,
                            message,
                        ],
                        capture_output=True,
                        check=True,
                        text=True,
                    )
                    body = f"\x1b[{sgr}m{tag}\x1b[0m" if color == "1" and sgr else tag
                    expected = f"[{body}] {component}: {message}\n"
                    self.assertEqual(result.stderr if stderr else result.stdout, expected)
                    self.assertEqual(result.stdout if stderr else result.stderr, "")


if __name__ == "__main__":
    unittest.main()
