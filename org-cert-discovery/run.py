# Garante imports relativos ao rodar `python src/main.py`
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from main import main

if __name__ == "__main__":
    raise SystemExit(main())
