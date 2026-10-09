import sys
from pathlib import Path

# Lets a clone run without installing; in the image src/ is gone and the installed package is used.
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from simple_socks5.main import cli  # noqa: E402

if __name__ == "__main__":
    cli()
