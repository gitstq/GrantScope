#!/usr/bin/env python3
"""Build a single-file, zero-dependency zipapp: ``dist/grantscope.pyz``.

    python build.py
    python dist/grantscope.pyz --version
    python dist/grantscope.pyz audit examples/good

The archive contains the whole package plus a tiny root ``__main__.py``, and
runs on any platform with Python >= 3.8. No build dependencies are required:
``zipapp`` is part of the standard library.
"""

from __future__ import annotations

import argparse
import shutil
import stat
import subprocess
import sys
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PACKAGE = ROOT / "grantscope"
BUILD_DIR = ROOT / ".build_tmp"
DEFAULT_OUTPUT = ROOT / "dist" / "grantscope.pyz"

MAIN = """\
from grantscope.cli import main
raise SystemExit(main())
"""


def build(output: Path, interpreter: str = "/usr/bin/env python3") -> Path:
    if not PACKAGE.is_dir():
        raise SystemExit("grantscope/ package not found; run from the repository root")
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
    BUILD_DIR.mkdir()

    shutil.copytree(PACKAGE, BUILD_DIR / "grantscope",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (BUILD_DIR / "__main__.py").write_text(MAIN, encoding="utf-8")

    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()
    zipapp.create_archive(
        BUILD_DIR,
        target=str(output),
        interpreter=interpreter,
        compressed=True,
    )
    shutil.rmtree(BUILD_DIR)

    # Make the shebang executable on POSIX; harmless on Windows.
    try:
        mode = output.stat().st_mode
        output.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass
    return output


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Build the GrantScope zipapp")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="target .pyz path")
    parser.add_argument("--interpreter", default="/usr/bin/env python3",
                        help="shebang interpreter (default: /usr/bin/env python3)")
    args = parser.parse_args(argv)

    out = Path(args.output)
    if not out.is_absolute():
        out = (ROOT / out).resolve()
    built = build(out, args.interpreter)
    size_kb = built.stat().st_size / 1024.0
    print("built %s (%.1f KiB)" % (built, size_kb))

    # Smoke-test the archive itself, not just the source tree.
    proc = subprocess.run(
        [sys.executable, str(built), "version"],
        capture_output=True, text=True, timeout=60,
    )
    check = proc.stdout.strip()
    if proc.returncode != 0 or "GrantScope" not in check:
        raise SystemExit("zipapp smoke test failed: %r %r" % (check, proc.stderr))
    print("smoke test: %s" % check)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
