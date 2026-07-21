#!/usr/bin/env python3
"""Scoped declarative ad blocking for the shared PrivDNS MITM sidecar."""
from __future__ import annotations

import base64
import json
import logging
import os
import re
import shutil
import subprocess

try:
    from mitmproxy import ctx as MITM_CTX
    from mitmproxy import http as MITM_HTTP
except ImportError:  # Unit tests use a small response factory instead.
    MITM_CTX = None
    MITM_HTTP = None

STATE_PATH = "/var/lib/pdg-wloc/adblock.json"
RULES_PATH = "/var/lib/pdg-wloc/adblock-rules.json"
MAX_BODY_BYTES = 4 * 1024 * 1024
JQ_TIMEOUT = 1.0
REQUEST_ACTIONS = {
    "reject", "reject-200", "reject-dict", "reject-img", "mock-response-body",
    "request-header-mock",
}
JSON_ACTIONS = {
    "response-body-json-del", "response-body-json-jq", "response-body-json-replace",
}
BODY_ACTIONS = {
    "response-body-replace-regex", "response-body-text-replace",
    "response-body-html-remove", "response-body-html-json-jq",
}
RESPONSE_CONTROL_ACTIONS = {"response-request-header-mock"}
TRANSPARENT_GIF = base64.b64decode("R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs=")
LOG = logging.getLogger("pdg-adblock")


def _log(level, message, *args):
    rendered = message % args if args else message
    if MITM_CTX is not None:
        mitm_log = getattr(MITM_CTX, "log", None)
        method = getattr(mitm_log, level, None)
        if method is None and level == "warning":
            method = getattr(mitm_log, "warn", None)
        if callable(method):
            method(rendered)
            return
        LOG.log(getattr(logging, level.upper(), logging.INFO), rendered)
    else:
        getattr(LOG, level)(rendered)


def _stamp(path):
    try:
        stat = os.stat(path)
        return stat.st_mtime_ns, stat.st_size
    except OSError:
        return None


def _load_enabled(path):
    try:
        with open(path, encoding="utf-8") as file:
            return bool(json.load(file).get("enabled"))
    except (OSError, AttributeError, json.JSONDecodeError):
        return False


def _path_parts(path):
    path = str(path).strip().lstrip(".")
    path = re.sub(r"\[['\"]([^'\"]+)['\"]\]", r".\1", path)
    parts = []
    for key, index in re.findall(r"(?:^|\.)([^.\[]+)|\[(\d+)\]", path):
        parts.append(int(index) if index else key)
    return parts


def _resolve_parent(value, parts):
    current = value
    for part in parts[:-1]:
        if isinstance(part, int) and isinstance(current, list) and 0 <= part < len(current):
            current = current[part]
        elif isinstance(part, str) and isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None, None
    return current, parts[-1] if parts else None


def json_set(value, path, replacement):
    parts = _path_parts(path)
    parent, key = _resolve_parent(value, parts)
    if isinstance(key, int) and isinstance(parent, list) and 0 <= key < len(parent):
        parent[key] = replacement
        return True
    if isinstance(key, str) and isinstance(parent, dict):
        parent[key] = replacement
        return True
    return False


def json_delete(value, path):
    parts = _path_parts(path)
    parent, key = _resolve_parent(value, parts)
    if isinstance(key, int) and isinstance(parent, list) and 0 <= key < len(parent):
        del parent[key]
        return True
    if isinstance(key, str) and isinstance(parent, dict) and key in parent:
        del parent[key]
        return True
    return False


def run_jq(value, program, jq_bin=None):
    jq = jq_bin or shutil.which("jq")
    if not jq:
        raise RuntimeError("jq is not installed")
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    result = subprocess.run(
        [jq, "-c", str(program)], input=encoded, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=JQ_TIMEOUT, check=False,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace").strip()[-160:]
        raise RuntimeError("jq failed" + ((": " + detail) if detail else ""))
    if not result.stdout or len(result.stdout) > MAX_BODY_BYTES:
        raise RuntimeError("jq returned an empty or oversized body")
    return json.loads(result.stdout)


def _default_response(status, body, headers):
    if MITM_HTTP is None:
        raise RuntimeError("mitmproxy response factory is unavailable")
    return MITM_HTTP.Response.make(status, body, headers)


def _response_body(response):
    getter = getattr(response, "get_content", None)
    if callable(getter):
        try:
            return getter(strict=False) or b""
        except TypeError:
            return getter() or b""
    return getattr(response, "content", None) or b""


def _replace_response_body(response, body):
    setter = getattr(response, "set_content", None)
    if callable(setter):
        setter(body)
        return
    response.content = body
    for key in list(response.headers.keys()):
        if str(key).lower() == "content-length":
            response.headers.pop(key, None)


def _header_value(headers, name):
    name = str(name).lower()
    for key, value in getattr(headers, "items", lambda: ())():
        if str(key).lower() == name:
            return str(value)
    return ""


def _request_header_matches(flow, arguments):
    headers = getattr(flow.request, "headers", {})
    matches = []
    for condition in arguments.get("headers", []):
        value = _header_value(headers, condition.get("name", ""))
        matches.append(bool(re.search(str(condition.get("pattern", "")), value)))
    return (all(matches) if arguments.get("mode") == "all" else any(matches)) \
        if matches else False


def replace_text_pairs(text, pairs):
    changed = 0
    for before, after in pairs:
        count = text.count(before)
        if count:
            text = text.replace(before, after)
            changed += count
    return text, changed


def remove_html_elements(text, tag, markers):
    token_re = re.compile(rf"</?{re.escape(tag)}\b[^>]*>", re.IGNORECASE)
    removed = 0
    for marker in markers:
        search_from = 0
        while True:
            marker_at = text.find(marker, search_from)
            if marker_at < 0:
                break
            opening_at = text.lower().rfind("<" + tag.lower(), 0, marker_at + 1)
            opening = token_re.match(text, opening_at) if opening_at >= 0 else None
            if opening is None or opening.group(0).lstrip().startswith("</"):
                search_from = marker_at + len(marker)
                continue
            depth = 0
            end = None
            for token in token_re.finditer(text, opening.start()):
                if token.group(0).lstrip().startswith("</"):
                    depth -= 1
                    if depth == 0:
                        end = token.end()
                        break
                elif not token.group(0).rstrip().endswith("/>"):
                    depth += 1
            if end is None:
                search_from = marker_at + len(marker)
                continue
            text = text[:opening.start()] + text[end:]
            search_from = opening.start()
            removed += 1
    return text, removed


def rewrite_embedded_json(text, element_id, program):
    pattern = re.compile(
        r"(<script\b(?=[^>]*\bid\s*=\s*(['\"])" + re.escape(element_id)
        + r"\2)[^>]*>)(.*?)(</script\s*>)",
        re.IGNORECASE | re.DOTALL,
    )
    changed = 0

    def replace(match):
        nonlocal changed
        value = json.loads(match.group(3))
        value = run_jq(value, program)
        changed += 1
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        # JSON embedded in a script element must not be able to terminate the
        # element. Preserve the decoded value while keeping HTML-significant
        # characters and JavaScript line separators escaped.
        encoded = (encoded.replace("&", r"\u0026")
                   .replace("<", r"\u003c")
                   .replace(">", r"\u003e")
                   .replace("\u2028", r"\u2028")
                   .replace("\u2029", r"\u2029"))
        return match.group(1) + encoded + match.group(4)

    return pattern.sub(replace, text), changed


class RuleCache:
    def __init__(self, path=RULES_PATH):
        self.path = path
        self.stamp = object()
        self.hosts = set()
        self.request_rules = {}
        self.response_rules = {}
        self.request_fallback = []
        self.response_fallback = []

    def request_candidates(self, host):
        yield from self.request_rules.get(str(host).lower(), ())
        yield from self.request_fallback

    def response_candidates(self, host):
        yield from self.response_rules.get(str(host).lower(), ())
        yield from self.response_fallback

    def refresh(self):
        current = _stamp(self.path)
        if current == self.stamp:
            return
        self.stamp = current
        hosts = set()
        request_rules = {}
        response_rules = {}
        request_fallback = []
        response_fallback = []
        if current is not None:
            try:
                with open(self.path, encoding="utf-8") as file:
                    payload = json.load(file)
                hosts = {str(host).lower() for host in payload.get("hosts", [])
                         if isinstance(host, str)}
                for raw in payload.get("rules", []):
                    if not isinstance(raw, dict) or raw.get("action") not in (
                            REQUEST_ACTIONS | JSON_ACTIONS |
                            BODY_ACTIONS | RESPONSE_CONTROL_ACTIONS |
                            {"response-header-add"}):
                        continue
                    try:
                        compiled = re.compile(str(raw["pattern"]))
                    except (KeyError, re.error):
                        continue
                    rule = dict(raw)
                    rule["compiled"] = compiled
                    is_request = rule["action"] in REQUEST_ACTIONS
                    target = request_rules if is_request else response_rules
                    fallback = request_fallback if is_request else response_fallback
                    rule_hosts = raw.get("hosts")
                    if isinstance(rule_hosts, list):
                        for host in {str(value).lower() for value in rule_hosts
                                     if isinstance(value, str)} & hosts:
                            target.setdefault(host, []).append(rule)
                    else:
                        # Version 1 caches had no per-rule host index. Retain
                        # compatibility until the next scheduled compilation.
                        fallback.append(rule)
            except (OSError, AttributeError, json.JSONDecodeError) as exc:
                _log("warning", "adblock rules unavailable: %s", exc)
        self.hosts = hosts
        self.request_rules = request_rules
        self.response_rules = response_rules
        self.request_fallback = request_fallback
        self.response_fallback = response_fallback
        request_count = sum(map(len, request_rules.values())) + len(request_fallback)
        response_count = sum(map(len, response_rules.values())) + len(response_fallback)
        _log("info", "adblock rules loaded hosts=%s request=%s response=%s",
             len(hosts), request_count, response_count)


class AdblockAddon:
    def __init__(self, state_path=STATE_PATH, rules_path=RULES_PATH, response_factory=None):
        self.state_path = state_path
        self.state_stamp = object()
        self.enabled = False
        self.rules = RuleCache(rules_path)
        self.response_factory = response_factory or _default_response

    def _active(self, flow):
        current = _stamp(self.state_path)
        if current != self.state_stamp:
            self.state_stamp = current
            self.enabled = _load_enabled(self.state_path)
        if not self.enabled:
            return False
        self.rules.refresh()
        host = str(getattr(flow.request, "pretty_host", "")).lower()
        return host in self.rules.hosts

    @staticmethod
    def _url(flow):
        return str(getattr(flow.request, "pretty_url", "") or
                   getattr(flow.request, "url", ""))

    def _synthetic(self, rule, flow=None):
        action = rule["action"]
        arguments = rule.get("arguments", {})
        if action == "request-header-mock":
            if flow is None or not _request_header_matches(flow, arguments):
                return None
            body = str(arguments.get("body", "")).encode()
            content_type = {
                "json": "application/json", "html": "text/html; charset=utf-8",
                "text": "text/plain; charset=utf-8",
            }.get(str(arguments.get("content_type", "text")), "application/octet-stream")
            return int(arguments.get("status", 200)), body, {
                "content-type": content_type, "cache-control": "no-store",
            }
        if action == "reject":
            return 204, b"", {"cache-control": "no-store"}
        if action == "reject-200":
            return 200, b"", {"cache-control": "no-store"}
        if action == "reject-dict":
            return 200, b"{}", {"content-type": "application/json", "cache-control": "no-store"}
        if action == "reject-img":
            return 200, TRANSPARENT_GIF, {"content-type": "image/gif", "cache-control": "public, max-age=86400"}
        if action == "mock-response-body":
            body = str(arguments.get("body", ""))
            if arguments.get("base64"):
                body = base64.b64decode(body)
            else:
                body = body.encode()
            content_type = {
                "json": "application/json", "html": "text/html; charset=utf-8",
                "text": "text/plain; charset=utf-8",
            }.get(str(arguments.get("content_type", "text")), "application/octet-stream")
            return int(arguments.get("status", 200)), body, {
                "content-type": content_type, "cache-control": "no-store",
            }
        return None

    def request(self, flow):
        if not self._active(flow):
            return
        url = self._url(flow)
        host = str(getattr(flow.request, "pretty_host", "")).lower()
        for rule in self.rules.request_candidates(host):
            if not rule["compiled"].search(url):
                continue
            synthetic = self._synthetic(rule, flow)
            if synthetic is None:
                continue
            flow.response = self.response_factory(*synthetic)
            _log("info", "adblock request source=%s action=%s host=%s",
                 rule.get("source", "?"), rule["action"], flow.request.pretty_host)
            return

    def response(self, flow):
        if flow.response is None or not self._active(flow):
            return
        url = self._url(flow)
        host = str(getattr(flow.request, "pretty_host", "")).lower()
        matches = [rule for rule in self.rules.response_candidates(host)
                   if rule["compiled"].search(url)]
        if not matches:
            return
        body = _response_body(flow.response)
        if len(body) > MAX_BODY_BYTES:
            _log("warning", "adblock response skipped oversized host=%s bytes=%s",
                 flow.request.pretty_host, len(body))
            return
        json_value = None
        json_loaded = False
        json_dirty = False
        changed = False
        body_changed = False
        for rule in matches:
            action = rule["action"]
            arguments = rule.get("arguments", {})
            try:
                if action == "response-header-add":
                    values = arguments.get("values", [])
                    for index in range(0, len(values), 2):
                        flow.response.headers[str(values[index])] = str(values[index + 1])
                    changed = True
                    continue
                if action == "response-request-header-mock":
                    if not _request_header_matches(flow, arguments):
                        continue
                    json_loaded = False
                    json_dirty = False
                    body = str(arguments.get("body", "")).encode()
                    flow.response.status_code = int(arguments.get("status", 200))
                    flow.response.headers["content-type"] = {
                        "json": "application/json", "html": "text/html; charset=utf-8",
                        "text": "text/plain; charset=utf-8",
                    }.get(str(arguments.get("content_type", "text")),
                          "application/octet-stream")
                    changed = True
                    body_changed = True
                    continue
                if action in JSON_ACTIONS:
                    if not json_loaded:
                        json_value = json.loads(body.decode("utf-8"))
                        json_loaded = True
                    if action == "response-body-json-del":
                        rule_changed = False
                        for path in arguments.get("values", []):
                            rule_changed = json_delete(json_value, path) or rule_changed
                    elif action == "response-body-json-replace":
                        rule_changed = False
                        for path, value in arguments.get("pairs", []):
                            rule_changed = json_set(json_value, path, value) or rule_changed
                    else:
                        json_value = run_jq(json_value, arguments["program"])
                        rule_changed = True
                    changed = rule_changed or changed
                    json_dirty = rule_changed or json_dirty
                    continue
                if json_loaded:
                    if json_dirty:
                        body = json.dumps(json_value, ensure_ascii=False,
                                          separators=(",", ":")).encode()
                        body_changed = True
                    json_loaded = False
                    json_dirty = False
                if action == "response-body-replace-regex":
                    text = body.decode("utf-8")
                    replaced, count = re.subn(arguments["pattern"],
                                               arguments["replacement"], text)
                    if count:
                        body = replaced.encode()
                        changed = True
                        body_changed = True
                elif action == "response-body-text-replace":
                    text, count = replace_text_pairs(
                        body.decode("utf-8"), arguments.get("pairs", []))
                    if count:
                        body = text.encode()
                        changed = True
                        body_changed = True
                elif action == "response-body-html-remove":
                    text, count = remove_html_elements(
                        body.decode("utf-8"), arguments.get("tag", "div"),
                        arguments.get("markers", []))
                    if count:
                        body = text.encode()
                        changed = True
                        body_changed = True
                elif action == "response-body-html-json-jq":
                    text, count = rewrite_embedded_json(
                        body.decode("utf-8"), arguments["element_id"],
                        arguments["program"])
                    if count:
                        body = text.encode()
                        changed = True
                        body_changed = True
            except (KeyError, TypeError, ValueError, UnicodeError, re.error,
                    subprocess.SubprocessError, RuntimeError, json.JSONDecodeError) as exc:
                _log("warning", "adblock rule skipped source=%s action=%s error=%s",
                     rule.get("source", "?"), action, exc)
        if json_loaded and json_dirty:
            body = json.dumps(json_value, ensure_ascii=False, separators=(",", ":")).encode()
        if not changed:
            return
        if json_loaded and json_dirty:
            body_changed = True
        if body_changed:
            _replace_response_body(flow.response, body)
        _log("info", "adblock response host=%s rules=%s bytes=%s",
             flow.request.pretty_host, len(matches), len(body))


addons = [AdblockAddon()]
