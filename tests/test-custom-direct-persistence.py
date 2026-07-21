#!/usr/bin/env python3
"""The daily updater and installer must preserve Bot-managed direct domains."""
import os
import stat
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def executable(path, text):
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    rules = root / "rules"
    bot_dir = root / "bot"
    bin_dir = root / "bin"
    rules.mkdir(); bot_dir.mkdir(); bin_dir.mkdir()
    direct = rules / "custom_direct.txt"
    direct.write_text("# keep\ndomain:updates.example\n", encoding="utf-8")

    executable(bin_dir / "curl", """#!/usr/bin/env python3
import pathlib, sys
target = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])
target.write_text('# UPDATED test\\nDOMAIN-SUFFIX,example.cn\\n', encoding='utf-8')
""")
    executable(bin_dir / "systemctl", "#!/bin/sh\nexit 1\n")
    executable(bot_dir / "parse-chinamax.py", """#!/usr/bin/env python3
import pathlib, sys
pathlib.Path(sys.argv[2]).write_text('domain:example.cn\\n', encoding='utf-8')
""")
    executable(bot_dir / "parse-geosite.py", """#!/usr/bin/env python3
import pathlib, sys
out = pathlib.Path(sys.argv[2]); out.mkdir(parents=True, exist_ok=True)
for name in ('apple', 'geolocation-!cn', 'cn'):
    (out / ('geosite_' + name + '.txt')).write_text('domain:example.com\\n', encoding='utf-8')
""")
    env = dict(os.environ)
    env.update({
        "PATH": str(bin_dir) + os.pathsep + env["PATH"],
        "PDG_MOSDNS_RULES": str(rules),
        "PDG_BOT_DIR": str(bot_dir),
    })
    subprocess.run(
        ["bash", str(ROOT / "deploy/bot/update-rules.sh")],
        env=env, check=True, capture_output=True, text=True,
    )
    assert direct.read_text(encoding="utf-8") == "# keep\ndomain:updates.example\n"

install = (ROOT / "install.sh").read_text(encoding="utf-8")
assert ": > /etc/mosdns/rules/custom_direct.txt" not in install
assert "[[ -e /etc/mosdns/rules/custom_direct.txt ]]" in install

print("custom-direct persistence regression OK")
