#!/usr/bin/env python3
"""Regression tests for bound, one-use MITM plugin approvals."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pdg_bot", ROOT / "deploy/bot/pdg-bot.py")
bot = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bot)

SOURCE_ID = "a" * 12
CANDIDATE_SHA = "b" * 64
GENERATION = "c" * 64

bot._ADBLOCK_APPROVALS.clear()
token = bot._adblock_issue_approval(100, 200, SOURCE_ID, CANDIDATE_SHA, GENERATION)
assert token
approval, error = bot._adblock_consume_approval(token, 100, 201)
assert approval is None and "上下文不匹配" in error
approval, error = bot._adblock_consume_approval(token, 100, 200)
assert not error
assert approval["source_id"] == SOURCE_ID
assert approval["candidate_sha"] == CANDIDATE_SHA
assert approval["generation"] == GENERATION
approval, error = bot._adblock_consume_approval(token, 100, 200)
assert approval is None and "失效或已使用" in error

expired = bot._adblock_issue_approval(100, 200, SOURCE_ID, CANDIDATE_SHA, GENERATION)
bot._ADBLOCK_APPROVALS[expired]["expires_at"] = 0
approval, error = bot._adblock_consume_approval(expired, 100, 200)
assert approval is None and "失效或已使用" in error

review_url = "https://example.test/review"
review_source_id = bot._adblock_source_id(review_url)
original_lock = bot._mitm_config_lock
original_rules = bot._adblock_rules
original_config = bot._adblock_source_config
try:
    bot._mitm_config_lock = lambda: bot.contextlib.nullcontext()
    bot._adblock_rules = lambda: {"pending_updates": [{
        "url": review_url,
        "sha256": CANDIDATE_SHA,
    }]}
    bot._adblock_source_config = lambda strict=False: {"sources": []}
    ok, message = bot.approve_adblock_plugin_update(
        review_source_id, "d" * 64, GENERATION)
    assert not ok and "候选插件已变化" in message
    ok, message = bot.approve_adblock_plugin_update(
        review_source_id, CANDIDATE_SHA, GENERATION)
    assert not ok and "来源配置已变化" in message
finally:
    bot._mitm_config_lock = original_lock
    bot._adblock_rules = original_rules
    bot._adblock_source_config = original_config

pending = {
    "approved_sha256": "d" * 64,
    "sha256": CANDIDATE_SHA,
    "current_host_count": 1,
    "new_host_count": 1,
    "current_rule_count": 1,
    "new_rule_count": 1,
    "added_hosts": [],
    "removed_hosts": [],
    "added_rule_count": 1,
    "removed_rule_count": 1,
    "added_rules": [{
        "action": "response-header-add",
        "hosts": ["api.example.com"],
        "pattern": "^https://api.example.com/new$",
    }],
    "removed_rules": [{
        "action": "response-header-add",
        "hosts": ["api.example.com"],
        "pattern": "^https://api.example.com/old$",
    }],
}
source = {
    "id": SOURCE_ID,
    "name": "test plugin",
    "url": "https://example.test/plugin",
    "pending": pending,
}

original_sources = bot._adblock_module_sources
original_config = bot._adblock_source_config
original_edit = bot.edit
original_busy = bot.is_busy
try:
    bot._ADBLOCK_APPROVALS.clear()
    bot._adblock_module_sources = lambda: [source]
    bot._adblock_source_config = lambda strict=False: {"sources": []}
    bot.is_busy = lambda *_args: False
    rendered = []
    bot.edit = lambda _chat, _mid, text, keyboard=None: rendered.append((text, keyboard))
    bot.handle_cb(100, 9, "adsrc_upd:" + SOURCE_ID, actor_id=200)
    text, keyboard = rendered[-1]
    assert "新增规则: 1 条" in text
    assert "删除规则: 1 条" in text
    assert "api.example.com/new" in text
    callback = keyboard["inline_keyboard"][0][0]["callback_data"]
    assert callback.startswith("adsrc_upd_yes:")
    approval_token = callback.split(":", 1)[1]
    approval, error = bot._adblock_consume_approval(approval_token, 100, 200)
    assert not error and approval["source_id"] == SOURCE_ID
finally:
    bot._adblock_module_sources = original_sources
    bot._adblock_source_config = original_config
    bot.edit = original_edit
    bot.is_busy = original_busy
    bot._ADBLOCK_APPROVALS.clear()

print("adblock approval regression OK")
