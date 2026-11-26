#!/usr/bin/env python3
"""entropy-map - entry point.

    python main.py analyze suspicious.exe
    python main.py analyze pack.zip --strings --json
    python main.py sections client.dll
    python main.py carve dump.bin
"""

import sys

from entropymap.cli import main

if __name__ == "__main__":
    sys.exit(main())
