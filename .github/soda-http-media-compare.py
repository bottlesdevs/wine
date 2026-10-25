import json
import sys
from pathlib import Path

expected = [json.loads(line) for line in Path(sys.argv[1]).read_text(encoding="utf-8-sig").splitlines()]
actual = [json.loads(line) for line in Path(sys.argv[2]).read_text(encoding="utf-8-sig").splitlines()]
if expected != actual:
    print("HTTP media record counts:", len(expected), len(actual))
    for index, (before, after) in enumerate(zip(expected, actual)):
        if before != after:
            print(json.dumps({"index": index, "expected": before, "actual": after}))
            break
    raise SystemExit(1)
print(f"HTTP_MEDIA_RESULT records={len(actual)} differences=0")
