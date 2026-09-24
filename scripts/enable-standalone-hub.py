#!/usr/bin/env python3
"""Make pubhubs_hub/testhub<n> a standalone hub, by adding the YiviLogin module to its
homeserver.yaml.  Does nothing when the module is already listed.

Edits the file as text rather than through a yaml library, so the comments in it survive.
"""

import re
import sys
from pathlib import Path

MODULE = "conf.modules.pubhubs.YiviLogin"
# The module listed for real, not in a comment
LISTED = re.compile(rf"^\s*-\s*module:\s*{re.escape(MODULE)}\s*(#.*)?$", re.MULTILINE)
MODULE_ITEM = re.compile(r"^(\s*)-\s*module:", re.MULTILINE)
TESTHUBS = range(5)


def main():
    n = int(sys.argv[1])
    path = Path("pubhubs_hub") / f"testhub{n}" / "homeserver.yaml"
    if not path.exists():
        sys.exit(f"{path} does not exist; run 'mask run hub init testhub-dirs' first")

    text = path.read_text()
    if LISTED.search(text):
        print(f"{path} already lists {MODULE}")
        return

    modules = re.search(r"^modules:[ \t]*\n", text, re.MULTILINE)
    item = MODULE_ITEM.search(text, modules.end()) if modules else None
    if item is None:
        sys.exit(f"could not find the modules list in {path}; add {MODULE} by hand")
    indent = item.group(1)

    # Link to the other testhubs, to try the 'Other hubs' page; each needs its own
    # 'mask run hub standalone <n>' to actually be up.
    links = "".join(
        f"{indent}          - {{ name: 'Standalone testhub {i}', url: 'http://localhost:{8001 + i}' }}\n"
        for i in TESTHUBS
        if i != n
    )
    block = (
        f"{indent}- module: {MODULE} # added by 'mask run hub standalone {n}'\n"
        f"{indent}  config:\n"
        f"{indent}      hub_name: 'Standalone testhub {n}'\n"
        f"{indent}      linked_hubs:\n"
        f"{links}"
    )
    path.write_text(text[: modules.end()] + block + text[modules.end() :])
    print(f"added {MODULE} to {path}")


if __name__ == "__main__":
    main()
