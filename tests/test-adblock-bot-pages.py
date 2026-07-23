#!/usr/bin/env python3
"""Regression tests for MITM plugin approval and pagination UI."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pdg_bot", ROOT / "deploy/bot/pdg-bot.py")
bot = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bot)


def callbacks(keyboard):
    return [button["callback_data"] for row in keyboard["inline_keyboard"]
            for button in row]


sources = [{
    "id": f"source{i:06d}",
    "name": f"plugin {i}",
    "url": f"https://example.test/{i}",
    "pending": {"sha256": "new"} if i == 20 else None,
} for i in range(25)]

original_sources = bot._adblock_module_sources
try:
    bot._adblock_module_sources = lambda: sources

    text, keyboard = bot._adblock_sources_page()
    assert "当前: <b>25</b> 个" in text
    assert "adsrc_page:1" in callbacks(keyboard)
    assert "adsrc_upd:source000020" not in callbacks(keyboard)

    text, keyboard = bot._adblock_sources_page(2)
    assert "3/3" in [button["text"] for row in keyboard["inline_keyboard"]
                     for button in row]
    assert "adsrc_upd:source000020" in callbacks(keyboard)
    assert "adsrc_page:1" in callbacks(keyboard)

    text, keyboard = bot._adblock_sources_page(pending_only=True)
    assert "待批准 MITM 更新" in text
    assert "adsrc_upd:source000020" in callbacks(keyboard)
    assert all("adsrc_page:" not in callback for callback in callbacks(keyboard))
finally:
    bot._adblock_module_sources = original_sources


class ActiveService:
    stdout = "active\n"


original_active = bot._adblock_active
original_sh = bot.sh
original_rules = bot._adblock_rules
original_config = bot._adblock_source_config
original_routes = bot._adblock_compatibility_routes
try:
    bot._adblock_active = lambda: True
    bot.sh = lambda *_args, **_kwargs: ActiveService()
    bot._adblock_rules = lambda: {
        "generated_at": "now",
        "stats": {"pending_module_updates": 1},
    }
    bot._adblock_source_config = lambda: {}
    bot._adblock_compatibility_routes = lambda _config: []
    _text, keyboard = bot._adblock_page()
    assert "adsrc_pending_page:0" in callbacks(keyboard)
finally:
    bot._adblock_active = original_active
    bot.sh = original_sh
    bot._adblock_rules = original_rules
    bot._adblock_source_config = original_config
    bot._adblock_compatibility_routes = original_routes


print("adblock bot pagination regression OK")
