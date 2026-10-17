import sys

from .cli import main

# Guarded: the spawned load-generator processes import this module as __mp_main__
if __name__ == "__main__":
    sys.exit(main())
