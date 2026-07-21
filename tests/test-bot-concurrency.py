#!/usr/bin/env python3
"""Configuration mutations and Telegram connections must be thread-safe."""
import importlib.util
import json
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOT = ROOT / "deploy/bot/pdg-bot.py"
spec = importlib.util.spec_from_file_location("pdg_bot_concurrency", BOT)
bot = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bot)


class Response:
    def read(self):
        return b'{"ok":true}'


connections = []
connection_lock = threading.Lock()


class Connection:
    def __init__(self, *_args, **_kwargs):
        self.thread = threading.get_ident()
        with connection_lock:
            connections.append(self)

    def request(self, *_args, **_kwargs):
        assert self.thread == threading.get_ident()

    def getresponse(self):
        return Response()

    def close(self):
        pass


bot.http.client.HTTPSConnection = Connection
barrier = threading.Barrier(2)
results = []


def telegram_worker():
    barrier.wait(timeout=5)
    results.append(bot.post("sendMessage", {"chat_id": 1, "text": "x"}))


threads = [threading.Thread(target=telegram_worker) for _ in range(2)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join(timeout=5)
assert all(not thread.is_alive() for thread in threads)
assert len(connections) == 2
assert len({connection.thread for connection in connections}) == 2
assert results == [{"ok": True}, {"ok": True}]


class CommandResult:
    returncode = 0
    stdout = "active\n"
    stderr = ""


with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    bot.STATE = str(root / "state.json")
    bot.MIHOMO_CFG = str(root / "config.yaml")
    bot.RS_DIR = str(root / "rs")
    bot.CONFIG_LOCK_FILE = str(root / "pdg.lock")
    bot.WLOC_STATE = str(root / "wloc.json")
    bot.ADBLOCK_STATE = str(root / "adblock.json")
    bot.ADBLOCK_RULES = str(root / "adblock-rules.json")
    bot.ADBLOCK_SOURCES = str(root / "adblock-sources.json")
    (root / "rs").mkdir()
    Path(bot.STATE).write_text(json.dumps({
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"rules": [], "rule_set": [], "final": "direct"},
    }), encoding="utf-8")
    Path(bot.WLOC_STATE).write_text('{"enabled":false}', encoding="utf-8")
    Path(bot.ADBLOCK_STATE).write_text('{"enabled":false}', encoding="utf-8")
    Path(bot.ADBLOCK_RULES).write_text('{"hosts":[],"rules":[]}', encoding="utf-8")
    Path(bot.ADBLOCK_SOURCES).write_text('{"sources":[]}', encoding="utf-8")
    bot.sh = lambda *_args, **_kwargs: CommandResult()
    bot._svc_active = lambda *_args, **_kwargs: True

    write_barrier = threading.Barrier(2)
    outcomes = []

    def mutation_worker(value):
        write_barrier.wait(timeout=5)
        outcomes.append(bot.apply_sb(
            lambda config: config.setdefault("mutations", []).append(value)))

    writers = [threading.Thread(target=mutation_worker, args=(value,))
               for value in ("one", "two")]
    for writer in writers:
        writer.start()
    for writer in writers:
        writer.join(timeout=10)
    assert all(not writer.is_alive() for writer in writers)
    assert all(ok for ok, _message in outcomes)
    final = json.loads(Path(bot.STATE).read_text(encoding="utf-8"))
    assert set(final["mutations"]) == {"one", "two"}

print("bot concurrency regression OK")
