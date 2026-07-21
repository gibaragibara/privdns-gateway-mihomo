#!/usr/bin/env python3
"""Compile safe declarative rewrites from allowlisted Loon/Egern modules."""
from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import ipaddress
import json
import os
import pwd
import re
import shlex
import shutil
import subprocess
import tempfile
import time
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

DEFAULT_SOURCES = "/etc/privdns-gateway/adblock-sources.json"
DEFAULT_OUTPUT = "/var/lib/pdg-wloc/adblock-rules.json"
DEFAULT_DOMAIN_OUTPUT = "/etc/mihomo/rs/__pdg_adblock_reject.mrs"
DEFAULT_CLASSICAL_OUTPUT = "/etc/mihomo/rs/__pdg_adblock_reject_classical.yaml"
DEFAULT_MODULE_CACHE = "/var/lib/pdg-wloc/adblock-modules"
USER_AGENT = "Egern/1.22.0 CFNetwork/1498.700.2 Darwin/23.6.0"
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_DOMAIN_SOURCE_BYTES = 16 * 1024 * 1024
MAX_DOMAIN_JSON_CHARS = 8 * 1024 * 1024
MAX_ADBLOCK_SOURCES = 64
MAX_MITM_EXCLUDED_HOSTS = 256
MAX_DOMAIN_SOURCE_LINES = 500_000
MAX_DOMAIN_RULES_PER_SOURCE = 400_000
MAX_DOMAIN_RULES_TOTAL = 600_000
MAX_LOCAL_DOMAIN_RULES = 4096
MAX_DOMAIN_LINE_CHARS = 4096
MAX_PINNED_RESOURCES = 128
MAX_SCRIPT_CONVERSION_ENTRIES = 512
MAX_SCRIPT_CONVERSION_RULES = 1024
MAX_JQ_PROGRAM_CHARS = 32_768
MAX_MITM_HOSTS_PER_SOURCE = 2048
MAX_MITM_HOSTS_TOTAL = 8192
MAX_MITM_RULES_PER_SOURCE = 4096
MAX_MITM_RULES_TOTAL = 20_000
SOURCE_FETCH_WORKERS = 4
SUPPORTED_ACTIONS = {
    "reject", "reject-200", "reject-dict", "reject-img",
    "mock-response-body", "response-body-json-del",
    "response-body-json-jq", "response-body-json-replace",
    "response-body-replace-regex", "response-header-add",
}
CONVERSION_ACTIONS = SUPPORTED_ACTIONS | {
    "request-header-mock", "response-body-text-replace",
    "response-body-html-remove", "response-body-html-json-jq",
    "response-request-header-mock",
}
REQUEST_ACTIONS = {
    "reject", "reject-200", "reject-dict", "reject-img",
    "mock-response-body", "request-header-mock",
}
BLOCKED_JQ_RE = re.compile(
    r"(?:\$ENV\b|\b(?:debug|env|include|import|input|inputs|module)\b)"
)
HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
DOMAIN_TOKEN_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_.-]{0,251}[a-z0-9_])?$"
)
CLASSICAL_TYPES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD", "DOMAIN-KEYWORD",
    "IP-CIDR", "IP-CIDR6",
}


class CompileError(ValueError):
    pass


def _fetch_text(url, timeout, max_bytes):
    parsed = urllib.parse.urlsplit(str(url))
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment):
        raise CompileError("source must be an HTTPS URL without credentials or fragments")
    curl = shutil.which("curl")
    if not curl:
        raise CompileError("curl is required to download protected module sources")
    try:
        result = subprocess.run(
            [curl, "-fsSL", "--proto", "=https", "--proto-redir", "=https",
             "--max-time", str(int(timeout)), "--max-filesize",
             str(max_bytes), "-A", USER_AGENT, "-H", "Accept: */*", str(url)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 5, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CompileError("module download timed out") from exc
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace").strip()[-160:]
        raise CompileError("source download failed" + ((": " + detail) if detail else ""))
    data = result.stdout
    if len(data) > max_bytes:
        raise CompileError(f"source exceeds {max_bytes // (1024 * 1024)} MiB")
    return data.decode("utf-8-sig")


def fetch_text(url, timeout=25):
    return _fetch_text(url, timeout, MAX_SOURCE_BYTES)


def fetch_domain_text(url, timeout=45):
    return _fetch_text(url, timeout, MAX_DOMAIN_SOURCE_BYTES)


def _scalar(token):
    token = str(token)
    try:
        return json.loads(token)
    except json.JSONDecodeError:
        return token


def _tokens(arguments):
    try:
        return shlex.split(arguments, posix=True)
    except ValueError as exc:
        raise CompileError(f"invalid rewrite arguments: {exc}") from exc


def _https_url(value, label="resource"):
    value = str(value or "").strip()
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment or len(value) > 2000):
        raise CompileError(f"{label} must be an HTTPS URL without credentials or fragments")
    return value


def _validate_jq_program(program, max_chars=MAX_JQ_PROGRAM_CHARS):
    program = str(program)
    if not program or len(program) > max_chars or BLOCKED_JQ_RE.search(program):
        raise CompileError("jq program uses a blocked capability or exceeds the size limit")
    return program


def _mock_arguments(arguments):
    status_match = re.search(r"(?:^|\s)status-code=(\d{3})(?:\s|$)", arguments)
    type_match = re.search(r"(?:^|\s)data-type=([A-Za-z0-9_-]+)(?:\s|$)", arguments)
    base64_match = re.search(r"(?:^|\s)mock-data-is-base64=(true|false)(?:\s|$)", arguments)
    encoded = bool(base64_match and base64_match.group(1) == "true")
    data_match = re.search(
        r'(?:^|\s)data="(.*)"(?:\s+mock-data-is-base64=(?:true|false))?\s*$',
        arguments,
    )
    if data_match:
        body = data_match.group(1)
    else:
        plain_match = re.search(r"(?:^|\s)data=([^\s]+)", arguments)
        body = plain_match.group(1) if plain_match else ""
    if encoded:
        try:
            base64.b64decode(body, validate=True)
        except ValueError as exc:
            raise CompileError("invalid base64 mock body") from exc
    return {
        "status": int(status_match.group(1)) if status_match else 200,
        "content_type": (type_match.group(1) if type_match else "text"),
        "body": body,
        "base64": encoded,
    }


def parse_action(action, arguments):
    if action in {"reject", "reject-200", "reject-dict", "reject-img"}:
        return {}
    if action == "mock-response-body":
        return _mock_arguments(arguments)
    if action in {"response-body-json-del", "response-header-add"}:
        values = _tokens(arguments)
        if not values:
            raise CompileError(f"{action} requires arguments")
        if action == "response-header-add" and len(values) % 2:
            raise CompileError("response-header-add requires header/value pairs")
        return {"values": values}
    if action == "response-body-json-replace":
        values = _tokens(arguments)
        if not values or len(values) % 2:
            raise CompileError("response-body-json-replace requires path/value pairs")
        return {"pairs": [[values[i], _scalar(values[i + 1])]
                           for i in range(0, len(values), 2)]}
    if action == "response-body-json-jq":
        values = _tokens(arguments)
        if len(values) != 1 or values[0].startswith("jq-path="):
            raise CompileError("external jq programs are not imported")
        return {"program": _validate_jq_program(values[0], 2000)}
    if action == "response-body-replace-regex":
        values = _tokens(arguments)
        if len(values) != 2:
            raise CompileError("response-body-replace-regex requires pattern/replacement")
        re.compile(values[0])
        return {"pattern": values[0], "replacement": values[1]}
    raise CompileError(f"unsupported action {action}")


def _string_list(value, label, limit=64, item_chars=4096):
    if (not isinstance(value, list) or not value or len(value) > limit
            or any(not isinstance(item, str) or not item or len(item) > item_chars
                   for item in value)):
        raise CompileError(f"{label} must be a non-empty string list")
    return list(value)


def _conversion_arguments(action, arguments):
    if not isinstance(arguments, dict):
        raise CompileError("script conversion arguments must be an object")
    if action in {"reject", "reject-200", "reject-dict", "reject-img"}:
        return {}
    if action == "mock-response-body":
        status = int(arguments.get("status", 200))
        content_type = str(arguments.get("content_type", "text"))
        body = str(arguments.get("body", ""))
        encoded = bool(arguments.get("base64", False))
        if not 100 <= status <= 599 or content_type not in {"text", "json", "html", "binary"}:
            raise CompileError("mock response metadata is invalid")
        if encoded:
            try:
                base64.b64decode(body, validate=True)
            except ValueError as exc:
                raise CompileError("mock response base64 body is invalid") from exc
        elif len(body.encode()) > 65_536:
            raise CompileError("mock response body is oversized")
        return {"status": status, "content_type": content_type,
                "body": body, "base64": encoded}
    if action == "response-body-json-jq":
        return {"program": _validate_jq_program(arguments.get("program", ""))}
    if action == "response-body-json-del":
        return {"values": _string_list(arguments.get("values"), "JSON delete paths")}
    if action == "response-body-json-replace":
        pairs = arguments.get("pairs")
        if (not isinstance(pairs, list) or not pairs or len(pairs) > 64
                or any(not isinstance(pair, list) or len(pair) != 2
                       or not isinstance(pair[0], str) or not pair[0]
                       for pair in pairs)):
            raise CompileError("JSON replacement pairs are invalid")
        return {"pairs": pairs}
    if action == "response-header-add":
        values = _string_list(arguments.get("values"), "response headers", limit=32)
        if len(values) % 2:
            raise CompileError("response headers require name/value pairs")
        return {"values": values}
    if action == "response-body-replace-regex":
        pattern = str(arguments.get("pattern", ""))
        replacement = arguments.get("replacement")
        if not pattern or len(pattern) > 4096 or not isinstance(replacement, str):
            raise CompileError("response regex replacement is invalid")
        re.compile(pattern)
        return {"pattern": pattern, "replacement": replacement}
    if action == "response-body-text-replace":
        pairs = arguments.get("pairs")
        if (not isinstance(pairs, list) or not pairs or len(pairs) > 32
                or any(not isinstance(pair, list) or len(pair) != 2
                       or not isinstance(pair[0], str) or not pair[0]
                       or not isinstance(pair[1], str)
                       or len(pair[0]) > 16_384 or len(pair[1]) > 16_384
                       for pair in pairs)):
            raise CompileError("text replacement pairs are invalid")
        return {"pairs": pairs}
    if action == "response-body-html-remove":
        tag = str(arguments.get("tag", "div")).lower()
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", tag):
            raise CompileError("HTML removal tag is invalid")
        markers = _string_list(arguments.get("markers"), "HTML removal markers", limit=16,
                               item_chars=256)
        return {"tag": tag, "markers": markers}
    if action == "response-body-html-json-jq":
        element_id = str(arguments.get("element_id", ""))
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", element_id):
            raise CompileError("embedded JSON element id is invalid")
        return {
            "element_id": element_id,
            "program": _validate_jq_program(arguments.get("program", "")),
        }
    if action in {"request-header-mock", "response-request-header-mock"}:
        headers = arguments.get("headers")
        if not isinstance(headers, list) or not headers or len(headers) > 8:
            raise CompileError("request header conditions are invalid")
        parsed_headers = []
        for item in headers:
            if not isinstance(item, dict):
                raise CompileError("request header condition must be an object")
            name = str(item.get("name", "")).strip().lower()
            pattern = str(item.get("pattern", ""))
            if (not re.fullmatch(r"[a-z0-9-]{1,64}", name) or not pattern
                    or len(pattern) > 2048):
                raise CompileError("request header condition is invalid")
            re.compile(pattern)
            parsed_headers.append({"name": name, "pattern": pattern})
        mode = str(arguments.get("mode", "any")).lower()
        if mode not in {"any", "all"}:
            raise CompileError("request header condition mode must be any or all")
        status = int(arguments.get("status", 200))
        body = str(arguments.get("body", ""))
        content_type = str(arguments.get("content_type", "text"))
        if not 100 <= status <= 599 or len(body.encode()) > 65_536:
            raise CompileError("request header mock response is invalid")
        if content_type not in {"text", "json", "html", "binary"}:
            raise CompileError("request header mock content type is invalid")
        return {
            "headers": parsed_headers, "mode": mode, "status": status,
            "body": body, "content_type": content_type,
        }
    raise CompileError(f"unsupported script conversion action {action}")


def _script_declarations(lines):
    scripts = []
    for line in lines:
        fields = line.split(None, 2)
        if not fields or fields[0] not in {"http-request", "http-response"}:
            continue
        if len(fields) != 3:
            scripts.append({"phase": "", "pattern": "", "script_url": ""})
            continue
        directive, pattern, remainder = fields
        match = re.search(
            r"(?:^|,\s*)(?:script-path|script_url)\s*=\s*(\"[^\"]+\"|[^,\s]+)",
            remainder,
        )
        script_url = match.group(1).strip('"') if match else ""
        try:
            re.compile(pattern)
        except re.error:
            pattern = ""
        scripts.append({
            "phase": directive.split("-", 1)[1],
            "pattern": pattern,
            "script_url": script_url,
        })
    return scripts


def _external_jq_url(arguments):
    values = _tokens(arguments)
    if len(values) != 1 or not values[0].startswith("jq-path="):
        return None
    return _https_url(values[0].split("=", 1)[1], "jq-path")


def _module_host_scope(lines):
    scope = {
        "exact": set(), "suffixes": set(),
        "patterns": set(), "excluded_exact": set(),
        "excluded_suffixes": set(), "excluded_patterns": set(),
    }
    skipped = 0
    for line in lines:
        match = re.match(r"hostname\s*=\s*(.*)$", line, re.IGNORECASE)
        if not match:
            continue
        for item in match.group(1).split(","):
            token = item.strip().lower().rstrip(".")
            if not token or token in {"%append%", "%prepend%"}:
                continue
            excluded = token.startswith("-")
            if excluded:
                token = token[1:].strip()
            wildcard = token.startswith("*.") and not any(
                char in token[2:] for char in "*?[]")
            host = token[2:] if wildcard else token
            glob = any(char in host for char in "*?")
            valid_glob = (glob and "[" not in host and "]" not in host
                          and re.fullmatch(r"(?=.{1,253}$)[a-z0-9*?](?:[a-z0-9.*?-]*"
                                           r"[a-z0-9*?])?", host)
                          and "." in host and ".." not in host)
            if not HOST_RE.fullmatch(host) and not valid_glob:
                skipped += 1
                continue
            if wildcard:
                key = "excluded_suffixes" if excluded else "suffixes"
            elif glob:
                key = "excluded_patterns" if excluded else "patterns"
            else:
                key = "excluded_exact" if excluded else "exact"
            scope[key].add(host)
    return scope, skipped


def _expand_literal_host_regex(expression, limit=64):
    """Expand a small, literal-only hostname regex into exact hostnames."""
    expression = str(expression)
    position = 0

    def combine(left, right):
        if len(left) * len(right) > limit:
            raise CompileError("hostname regex expands to too many alternatives")
        return [prefix + suffix for prefix in left for suffix in right]

    def parse_group(stop=False):
        nonlocal position
        alternatives = []
        current = [""]
        while position < len(expression):
            char = expression[position]
            if char == ")":
                if not stop:
                    raise CompileError("unbalanced hostname regex group")
                position += 1
                alternatives.extend(current)
                return alternatives
            if char == "|":
                alternatives.extend(current)
                if len(alternatives) > limit:
                    raise CompileError("hostname regex has too many alternatives")
                current = [""]
                position += 1
                continue
            if char == "(":
                position += 1
                if expression.startswith("?:", position):
                    position += 2
                group = parse_group(stop=True)
                current = combine(current, group)
                continue
            if char == "\\":
                position += 1
                if position >= len(expression) or expression[position] not in ".-_":
                    raise CompileError("hostname regex contains a non-literal escape")
                token = expression[position]
                position += 1
            elif char.isascii() and (char.isalnum() or char in "-_"):
                token = char
                position += 1
            else:
                raise CompileError("hostname regex is not literal-only")
            current = [value + token for value in current]
        if stop:
            raise CompileError("unbalanced hostname regex group")
        alternatives.extend(current)
        return alternatives

    values = parse_group()
    hosts = {value.lower().rstrip(".") for value in values
             if HOST_RE.fullmatch(value.lower().rstrip("."))}
    if not hosts or len(hosts) > limit:
        raise CompileError("hostname regex does not resolve to exact hostnames")
    return hosts


def _pattern_literal_hosts(pattern):
    value = str(pattern).replace(r"\/", "/")
    marker = value.find("://")
    if marker < 0:
        return set()
    authority = value[marker + 3:].split("/", 1)[0]
    try:
        return _expand_literal_host_regex(authority)
    except CompileError:
        return set()


def _host_in_suffix(host, suffix):
    return host.endswith("." + suffix)


def _host_allowed(host, scope):
    positive = host in scope["exact"] or any(
        _host_in_suffix(host, suffix) for suffix in scope["suffixes"]) or any(
        fnmatch.fnmatchcase(host, pattern) for pattern in scope["patterns"])
    excluded = host in scope["excluded_exact"] or any(
        _host_in_suffix(host, suffix) for suffix in scope["excluded_suffixes"]) or any(
        fnmatch.fnmatchcase(host, pattern) for pattern in scope["excluded_patterns"])
    return positive and not excluded


def _pattern_target_hosts(pattern, scope, explicit_hosts=()):
    value = str(pattern).replace(r"\/", "/")
    candidates = set(explicit_hosts)
    if "://" in value:
        candidates.update(_pattern_literal_hosts(pattern))
    else:
        # A path-only expression may apply to every exact declared host. A
        # wildcard scope still requires explicit exact hosts to avoid broad MITM.
        candidates.update(scope["exact"])
    return {host for host in candidates if _host_allowed(host, scope)}


def _private_items(config, key, limit):
    items = config.get(key, []) if isinstance(config, dict) else []
    if not isinstance(items, list) or len(items) > limit:
        raise CompileError(f"{key} must be a list with at most {limit} entries")
    if any(not isinstance(item, dict) for item in items):
        raise CompileError(f"{key} entries must be objects")
    return items


def _resource_pins(config):
    conversions = _private_items(
        config, "script_conversions", MAX_PINNED_RESOURCES)
    jq_pins = _private_items(config, "external_jq_pins", MAX_PINNED_RESOURCES)
    pins = {}
    labels = {}
    resources = ([(item, "script_url", "script conversion") for item in conversions]
                 + [(item, "url", "external jq") for item in jq_pins])
    for item, url_key, label in resources:
        url = _https_url(item.get(url_key), label)
        digest = str(item.get("sha256", "")).lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise CompileError(f"{label} requires a lowercase SHA256")
        if url in pins and pins[url] != digest:
            raise CompileError(f"conflicting SHA256 pins for {url}")
        pins[url] = digest
        labels[url] = str(item.get("name") or label)[:80]
    if len(pins) > MAX_PINNED_RESOURCES:
        raise CompileError(
            f"private resources exceed the {MAX_PINNED_RESOURCES}-resource limit")
    return conversions, jq_pins, pins, labels


def _fetch_pinned_resources(config, fetcher):
    conversions, jq_pins, pins, labels = _resource_pins(config)
    active = {}
    stale = set()
    failures = []
    items = [{"url": url} for url in pins]
    for batch in _fetched_source_batches(items, fetcher):
        for item, future in batch:
            url = item["url"]
            try:
                text = future.result()
            except Exception as exc:
                failures.append({
                    "name": labels[url],
                    "error": f"pinned resource unavailable: {str(exc)[:160]}",
                })
                continue
            digest = hashlib.sha256(text.encode()).hexdigest()
            if digest != pins[url]:
                stale.add(url)
                continue
            active[url] = text
    return conversions, jq_pins, active, stale, failures


def _script_conversion_map(conversions, active_resources):
    result = {}
    configured_entries = 0
    configured_rules = 0
    active_entries = 0
    for group in conversions:
        script_url = _https_url(group.get("script_url"), "script conversion")
        entries = group.get("entries")
        if not isinstance(entries, list) or not entries:
            raise CompileError("script conversion entries must be a non-empty list")
        configured_entries += len(entries)
        if configured_entries > MAX_SCRIPT_CONVERSION_ENTRIES:
            raise CompileError(
                f"script conversions exceed the {MAX_SCRIPT_CONVERSION_ENTRIES}-entry limit")
        group_active = script_url in active_resources
        for entry in entries:
            if not isinstance(entry, dict):
                raise CompileError("script conversion entry must be an object")
            phase = str(entry.get("phase", "")).lower()
            pattern = str(entry.get("pattern", ""))
            if phase not in {"request", "response"} or not pattern or len(pattern) > 4096:
                raise CompileError("script conversion phase or pattern is invalid")
            re.compile(pattern)
            explicit_hosts = entry.get("hosts", group.get("hosts", []))
            if explicit_hosts:
                if (not isinstance(explicit_hosts, list)
                        or len(explicit_hosts) > MAX_MITM_HOSTS_PER_SOURCE):
                    raise CompileError("script conversion hosts must be a bounded list")
                normalized_hosts = []
                for value in explicit_hosts:
                    host = str(value).strip().lower().rstrip(".")
                    if not HOST_RE.fullmatch(host):
                        raise CompileError("script conversion host is invalid")
                    if host not in normalized_hosts:
                        normalized_hosts.append(host)
            else:
                normalized_hosts = []
            raw_rules = entry.get("rules")
            if not isinstance(raw_rules, list) or not raw_rules:
                raise CompileError("script conversion rules must be a non-empty list")
            configured_rules += len(raw_rules)
            if configured_rules > MAX_SCRIPT_CONVERSION_RULES:
                raise CompileError(
                    f"script conversions exceed the {MAX_SCRIPT_CONVERSION_RULES}-rule limit")
            compiled_rules = []
            for raw in raw_rules:
                if not isinstance(raw, dict):
                    raise CompileError("script conversion rule must be an object")
                action = str(raw.get("action", ""))
                if action not in CONVERSION_ACTIONS:
                    raise CompileError(f"unsupported script conversion action {action}")
                if (phase == "request") != (action in REQUEST_ACTIONS):
                    raise CompileError("script conversion action does not match its phase")
                rule_pattern = str(raw.get("pattern") or pattern)
                if not rule_pattern or len(rule_pattern) > 4096:
                    raise CompileError("script conversion rule pattern is invalid")
                re.compile(rule_pattern)
                compiled_rules.append({
                    "pattern": rule_pattern,
                    "action": action,
                    "arguments": _conversion_arguments(action, raw.get("arguments", {})),
                    "_hosts": normalized_hosts,
                })
            key = (script_url, phase, pattern)
            if key in result:
                raise CompileError("duplicate script conversion entry")
            if group_active:
                result[key] = compiled_rules
                active_entries += 1
    return result, {
        "script_conversion_entries": configured_entries,
        "active_script_conversion_entries": active_entries,
        "script_conversion_rules": configured_rules,
    }


def _external_jq_programs(jq_pins, active_resources):
    programs = {}
    for item in jq_pins:
        url = _https_url(item.get("url"), "external jq")
        if url in active_resources:
            programs[url] = _validate_jq_program(active_resources[url])
    return programs


def parse_module(text, name, source_url="", script_conversions=None, external_jq=None):
    sections = {}
    section = None
    for raw in str(text).splitlines():
        line = raw.strip()
        match = re.fullmatch(r"\[([^]]+)\]", line)
        if match:
            section = match.group(1)
            sections.setdefault(section, [])
            continue
        if not line or line.startswith("#") or section is None:
            continue
        sections.setdefault(section, []).append(line)

    host_scope, skipped_hosts = _module_host_scope(sections.get("MitM", []))
    scripts = _script_declarations(sections.get("Script", []))
    script_conversions = script_conversions or {}
    external_jq = external_jq or {}
    rules = []
    unsupported = Counter()
    invalid = 0
    imported_external_jq = 0
    for line in sections.get("Rewrite", []):
        try:
            pattern, remainder = line.split(None, 1)
            action, _, arguments = remainder.partition(" ")
        except ValueError:
            invalid += 1
            continue
        if action not in SUPPORTED_ACTIONS:
            unsupported[action or "unknown"] += 1
            continue
        try:
            re.compile(pattern)
            jq_url = (_external_jq_url(arguments.strip())
                      if action == "response-body-json-jq" else None)
            if jq_url is not None:
                if jq_url not in external_jq:
                    raise CompileError("external jq program is not pinned or changed")
                parsed = {"program": external_jq[jq_url]}
                imported_external_jq += 1
            else:
                parsed = parse_action(action, arguments.strip())
        except (CompileError, re.error):
            unsupported[action] += 1
            continue
        rules.append({
            "pattern": pattern,
            "action": action,
            "arguments": parsed,
            "source": str(name)[:80],
        })
        if len(rules) > MAX_MITM_RULES_PER_SOURCE:
            raise CompileError(
                f"module exceeds the {MAX_MITM_RULES_PER_SOURCE}-rewrite limit")

    converted_scripts = 0
    converted_script_rules = 0
    for script in scripts:
        templates = script_conversions.get((
            script["script_url"], script["phase"], script["pattern"]))
        if not templates:
            continue
        converted_scripts += 1
        for template in templates:
            rule = dict(template)
            rule["source"] = (str(name)[:65] + " (script)")[:80]
            rules.append(rule)
            converted_script_rules += 1
            if len(rules) > MAX_MITM_RULES_PER_SOURCE:
                raise CompileError(
                    f"module exceeds the {MAX_MITM_RULES_PER_SOURCE}-rewrite limit")

    active_hosts = set()
    executable_rules = []
    for rule in rules:
        explicit_hosts = rule.pop("_hosts", [])
        targets = sorted(_pattern_target_hosts(
            rule["pattern"], host_scope, explicit_hosts))
        rule["hosts"] = targets
        if targets:
            active_hosts.update(targets)
            executable_rules.append(rule)
    if len(active_hosts) > MAX_MITM_HOSTS_PER_SOURCE:
        raise CompileError(
            f"module exceeds the {MAX_MITM_HOSTS_PER_SOURCE}-host limit")

    return {
        "name": str(name)[:80],
        "url": str(source_url),
        "hosts": sorted(active_hosts),
        "rules": executable_rules,
        "stats": {
            "parsed_rewrites": len(rules),
            "supported_rewrites": len(executable_rules),
            "unreachable_rewrites": len(rules) - len(executable_rules),
            "converted_script_rules": converted_script_rules,
            "unsupported_rewrites": sum(unsupported.values()) + invalid,
            "unsupported_actions": dict(sorted(unsupported.items())),
            "script_declarations": len(scripts),
            "converted_scripts": converted_scripts,
            "unported_scripts": len(scripts) - converted_scripts,
            "imported_external_jq": imported_external_jq,
            "skipped_hosts": skipped_hosts,
            "declared_exact_hosts": len(host_scope["exact"]),
            "declared_wildcard_hosts": (len(host_scope["suffixes"])
                                        + len(host_scope["patterns"])),
            "excluded_module_hosts": (len(host_scope["excluded_exact"])
                                      + len(host_scope["excluded_suffixes"])
                                      + len(host_scope["excluded_patterns"])),
            "unused_hosts": len(host_scope["exact"] - active_hosts),
        },
    }


def _enabled_source_items(config, key):
    items = config.get(key, []) if isinstance(config, dict) else []
    if not isinstance(items, list):
        raise CompileError(f"{key} must be a list")
    enabled = [item for item in items
               if isinstance(item, dict) and item.get("enabled", True)]
    if len(enabled) > MAX_ADBLOCK_SOURCES:
        raise CompileError(f"{key} exceeds the {MAX_ADBLOCK_SOURCES}-source limit")
    return enabled


def _fetched_source_batches(items, fetcher):
    for offset in range(0, len(items), SOURCE_FETCH_WORKERS):
        batch = items[offset:offset + SOURCE_FETCH_WORKERS]
        with ThreadPoolExecutor(max_workers=len(batch)) as executor:
            pending = [(item, executor.submit(fetcher, str(item.get("url") or "")))
                       for item in batch]
            yield pending


def _module_digest(item, required=False):
    digest = str(item.get("sha256") or "").strip().lower()
    if not digest:
        if required:
            raise CompileError("module source is not approved; initialize or add its SHA256")
        return ""
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise CompileError("module source SHA256 is invalid")
    return digest


def _module_cache_path(cache_dir, url, digest):
    source_id = hashlib.sha256(str(url).encode()).hexdigest()[:24]
    return os.path.join(str(cache_dir), f"{source_id}-{digest}.lpx")


def _read_module_cache(cache_dir, url, digest):
    if not cache_dir or not digest:
        return None
    path = _module_cache_path(cache_dir, url, digest)
    try:
        data = open(path, "rb").read(MAX_SOURCE_BYTES + 1)
    except OSError:
        return None
    if len(data) > MAX_SOURCE_BYTES or hashlib.sha256(data).hexdigest() != digest:
        return None
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def _write_module_cache(cache_dir, url, digest, text):
    if not cache_dir:
        return
    data = str(text).encode()
    if len(data) > MAX_SOURCE_BYTES or hashlib.sha256(data).hexdigest() != digest:
        raise CompileError("refusing to cache a module with mismatched SHA256")
    os.makedirs(cache_dir, mode=0o700, exist_ok=True)
    os.chmod(cache_dir, 0o700)
    destination = _module_cache_path(cache_dir, url, digest)
    fd, temporary = tempfile.mkstemp(prefix=".module-", dir=cache_dir)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(data)
            file.flush(); os.fsync(file.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def mitm_excluded_hosts(config):
    items = config.get("mitm_exclude_hosts", []) if isinstance(config, dict) else []
    if not isinstance(items, list):
        raise CompileError("mitm_exclude_hosts must be a list")
    if len(items) > MAX_MITM_EXCLUDED_HOSTS:
        raise CompileError(
            f"mitm_exclude_hosts exceeds the {MAX_MITM_EXCLUDED_HOSTS}-host limit")
    hosts = set()
    for value in items:
        if not isinstance(value, str):
            raise CompileError("mitm_exclude_hosts entries must be strings")
        host = value.strip().lower().rstrip(".")
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise CompileError("invalid excluded MITM hostname") from exc
        if not HOST_RE.fullmatch(host):
            raise CompileError("invalid excluded MITM hostname")
        hosts.add(host)
    return sorted(hosts)


def compile_sources(config, fetcher=fetch_text, module_cache_dir=None,
                    require_module_pins=False):
    items = _enabled_source_items(config, "sources")
    configured_exclusions = set(mitm_excluded_hosts(config))
    conversions, jq_pins, active_resources, stale_resources, resource_failures = \
        _fetch_pinned_resources(config, fetcher)
    conversion_map, conversion_stats = _script_conversion_map(
        conversions, active_resources)
    external_jq = _external_jq_programs(jq_pins, active_resources)
    compiled_sources = []
    rules = []
    declared_hosts = set()
    seen_rules = set()
    failures = list(resource_failures)
    warnings = []
    pending_updates = []
    cached_sources = 0
    excluded_rewrites = 0
    for batch in _fetched_source_batches(items, fetcher):
        for item, future in batch:
            name = str(item.get("name") or "unnamed")[:80]
            url = str(item.get("url") or "")
            try:
                approved_digest = _module_digest(item, required=require_module_pins)
                fetched_text = future.result()
                fetched_digest = hashlib.sha256(fetched_text.encode()).hexdigest()
                pending_text = None
                if approved_digest and fetched_digest != approved_digest:
                    selected_text = _read_module_cache(
                        module_cache_dir, url, approved_digest)
                    if selected_text is None:
                        raise CompileError(
                            "module changed and its approved last-known-good cache is missing")
                    pending_text = fetched_text
                else:
                    selected_text = fetched_text
                    if approved_digest:
                        _write_module_cache(
                            module_cache_dir, url, approved_digest, selected_text)
                module = parse_module(
                    selected_text, name, url,
                    script_conversions=conversion_map,
                    external_jq=external_jq,
                )
            except Exception as exc:  # try the approved cache when the network is unavailable
                try:
                    approved_digest = _module_digest(item, required=require_module_pins)
                    selected_text = _read_module_cache(
                        module_cache_dir, url, approved_digest)
                    if selected_text is None:
                        raise exc
                    module = parse_module(
                        selected_text, name, url,
                        script_conversions=conversion_map,
                        external_jq=external_jq,
                    )
                    cached_sources += 1
                    warnings.append({"name": name, "warning": "using approved cached module"})
                    pending_text = None
                    fetched_digest = ""
                except Exception as cache_exc:  # noqa: BLE001
                    failures.append({"name": name, "error": str(cache_exc)[:200]})
                    continue
            if pending_text is not None:
                update = {
                    "name": name, "url": url,
                    "approved_sha256": approved_digest,
                    "sha256": fetched_digest,
                    "current_host_count": len(module["hosts"]),
                    "current_rule_count": len(module["rules"]),
                }
                try:
                    candidate = parse_module(
                        pending_text, name, url,
                        script_conversions=conversion_map,
                        external_jq=external_jq,
                    )
                    update.update({
                        "new_host_count": len(candidate["hosts"]),
                        "new_rule_count": len(candidate["rules"]),
                        "added_hosts": sorted(set(candidate["hosts"]) - set(module["hosts"]))[:64],
                        "removed_hosts": sorted(set(module["hosts"]) - set(candidate["hosts"]))[:64],
                    })
                except Exception as exc:  # candidate is never activated on parse failure
                    update["candidate_error"] = str(exc)[:200]
                pending_updates.append(update)
            source_summary = {key: module[key] for key in ("name", "url", "stats")}
            if approved_digest:
                source_summary["sha256"] = approved_digest
            compiled_sources.append(source_summary)
            if not module["rules"]:
                continue
            declared_hosts.update(module["hosts"])
            if len(declared_hosts) > MAX_MITM_HOSTS_TOTAL:
                raise CompileError(
                    f"compiled MITM hosts exceed the {MAX_MITM_HOSTS_TOTAL}-host limit")
            for rule in module["rules"]:
                filtered_hosts = [host for host in rule["hosts"]
                                  if host not in configured_exclusions]
                if not filtered_hosts:
                    excluded_rewrites += 1
                    continue
                rule = {**rule, "hosts": filtered_hosts}
                key = json.dumps(rule, ensure_ascii=False, sort_keys=True)
                if key not in seen_rules:
                    seen_rules.add(key)
                    rules.append(rule)
                    if len(rules) > MAX_MITM_RULES_TOTAL:
                        raise CompileError(
                            f"compiled MITM rules exceed the {MAX_MITM_RULES_TOTAL}-rule limit")
    excluded_hosts = declared_hosts & configured_exclusions
    hosts = declared_hosts - configured_exclusions
    stats = {
        "source_count": len(compiled_sources),
        "failed_sources": len(failures),
        "host_count": len(hosts),
        "declared_host_count": len(declared_hosts),
        "excluded_host_count": len(excluded_hosts),
        "rule_count": len(rules),
        "unreachable_rewrites": sum(
            s["stats"].get("unreachable_rewrites", 0) for s in compiled_sources),
        "excluded_rewrites": excluded_rewrites,
        "pending_module_updates": len(pending_updates),
        "cached_module_sources": cached_sources,
        "script_declarations": sum(
            s["stats"].get("script_declarations", 0) for s in compiled_sources),
        "converted_scripts": sum(
            s["stats"].get("converted_scripts", 0) for s in compiled_sources),
        "unported_scripts": sum(s["stats"]["unported_scripts"] for s in compiled_sources),
        "converted_script_rules": sum(
            s["stats"].get("converted_script_rules", 0) for s in compiled_sources),
        "external_jq_pins": len(jq_pins),
        "active_external_jq_pins": len(external_jq),
        "imported_external_jq": sum(
            s["stats"].get("imported_external_jq", 0) for s in compiled_sources),
        "pinned_resource_failures": len(resource_failures),
        "stale_pinned_resources": len(stale_resources),
        "unsupported_rewrites": sum(s["stats"]["unsupported_rewrites"] for s in compiled_sources),
        "unused_hosts": sum(s["stats"].get("unused_hosts", 0) for s in compiled_sources),
    }
    stats.update(conversion_stats)
    return {
        "version": 2,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "hosts": sorted(hosts),
        "excluded_hosts": sorted(excluded_hosts),
        "rules": rules,
        "sources": compiled_sources,
        "failures": failures,
        "warnings": warnings,
        "pending_updates": pending_updates,
        "stats": stats,
    }


def _domain_token(value):
    value = str(value).strip().lower().rstrip(".")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise CompileError("invalid internationalized domain") from exc
    if not DOMAIN_TOKEN_RE.fullmatch(value) or ".." in value:
        raise CompileError("invalid domain token")
    return value


def _domain_pattern(value):
    value = str(value).strip().lower().rstrip(".")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise CompileError("wildcard domains must be ASCII") from exc
    if (not re.fullmatch(r"(?=.{1,253}$)[a-z0-9_*?](?:[a-z0-9_.*?-]{0,251}[a-z0-9_*?])?", value)
            or ".." in value or not any(char in value for char in "*?")):
        raise CompileError("invalid wildcard domain")
    return value


def _classical_rule(line):
    fields = [field.strip() for field in str(line).split(",")]
    if len(fields) < 2 or fields[0].upper() not in CLASSICAL_TYPES:
        raise CompileError("unsupported classical rule")
    kind = fields[0].upper()
    value = fields[1]
    if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
        value = _domain_token(value.lstrip("+."))
    elif kind == "DOMAIN-WILDCARD":
        value = _domain_pattern(value)
    elif kind == "DOMAIN-KEYWORD":
        value = value.lower()
        if not value or len(value) > 253 or any(ord(char) < 32 for char in value) or "," in value:
            raise CompileError("invalid domain keyword")
    else:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise CompileError("invalid IP network") from exc
        if (kind == "IP-CIDR") != (network.version == 4):
            raise CompileError("IP rule family mismatch")
        value = str(network)
    suffix = (",no-resolve" if kind in {"IP-CIDR", "IP-CIDR6"}
              and any(field.lower() == "no-resolve" for field in fields[2:]) else "")
    return f"{kind},{value}{suffix}"


def _yaml_scalar(value):
    value = str(value).strip()
    single = re.fullmatch(r"'((?:[^']|'')*)'\s*(?:#.*)?", value)
    if single:
        return single.group(1).replace("''", "'")
    if value.startswith('"'):
        try:
            decoded, end = json.JSONDecoder().raw_decode(value)
        except json.JSONDecodeError as exc:
            raise CompileError("invalid quoted YAML scalar") from exc
        tail = value[end:].strip()
        if not isinstance(decoded, str) or (tail and not tail.startswith("#")):
            raise CompileError("invalid quoted YAML scalar")
        return decoded
    value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
    if not value or value[0] in "&!|>{[":
        raise CompileError("unsupported YAML scalar")
    return value


def _domain_source_lines(text):
    text = str(text)
    line_count = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
    if line_count > MAX_DOMAIN_SOURCE_LINES:
        raise CompileError(
            f"domain source exceeds the {MAX_DOMAIN_SOURCE_LINES}-line limit")
    lines = text.split("\n")
    if any(len(line) > MAX_DOMAIN_LINE_CHARS for line in lines):
        raise CompileError(
            f"domain source contains a line longer than {MAX_DOMAIN_LINE_CHARS} characters")
    return lines


def _auto_source_entries(text):
    text = str(text)
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        if len(stripped) > MAX_DOMAIN_JSON_CHARS:
            raise CompileError(
                f"JSON domain source exceeds {MAX_DOMAIN_JSON_CHARS // (1024 * 1024)} MiB")
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            payload = payload.get("payload")
        if isinstance(payload, list):
            if len(payload) > MAX_DOMAIN_SOURCE_LINES:
                raise CompileError(
                    f"domain source exceeds the {MAX_DOMAIN_SOURCE_LINES}-entry limit")
            entries = [item for item in payload if isinstance(item, str)]
            return entries, len(payload) - len(entries)

    lines = _domain_source_lines(text)
    payload_index = None
    payload_indent = 0
    for index, raw in enumerate(lines):
        if re.fullmatch(r"\s*payload\s*:\s*(?:#.*)?", raw):
            payload_index = index
            payload_indent = len(raw) - len(raw.lstrip())
            break
    if payload_index is None:
        return lines, 0

    entries = []
    unsupported = 0
    for raw in lines[payload_index + 1:]:
        stripped_line = raw.strip()
        if not stripped_line or stripped_line.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        if not stripped_line.startswith("-"):
            if indent <= payload_indent:
                break
            unsupported += 1
            continue
        try:
            entries.append(_yaml_scalar(stripped_line[1:].strip()))
        except CompileError:
            unsupported += 1
    return entries, unsupported


def _auto_domain_rule(line):
    line = re.split(r"\s+#", str(line), maxsplit=1)[0].strip()
    kind = str(line).split(",", 1)[0].strip().upper()
    if kind in CLASSICAL_TYPES:
        return _classical_rule(line)
    suffix = line.startswith((".", "+."))
    value = line[2:] if line.startswith("+.") else line.lstrip(".")
    if any(char in value for char in "*?"):
        return "DOMAIN-WILDCARD," + _domain_pattern(value)
    return f"{'DOMAIN-SUFFIX' if suffix else 'DOMAIN'},{_domain_token(value)}"


def parse_domain_source(text, name, source_url="", source_format="classical"):
    source_format = str(source_format).strip().lower()
    if source_format not in {"auto", "classical", "domain-set"}:
        raise CompileError(f"unsupported domain source format {source_format}")
    rules = []
    seen = set()
    entries, unsupported = (_auto_source_entries(text) if source_format == "auto"
                            else (_domain_source_lines(text), 0))
    for raw in entries:
        if len(raw) > MAX_DOMAIN_LINE_CHARS:
            raise CompileError(
                f"domain source contains an entry longer than {MAX_DOMAIN_LINE_CHARS} characters")
        line = raw.strip()
        if not line or line.startswith(("#", ";", "!", "//")):
            continue
        try:
            if source_format == "auto":
                rule = _auto_domain_rule(line)
            elif source_format == "domain-set":
                suffix = line.startswith((".", "+."))
                value = _domain_token(line[2:] if line.startswith("+.") else line.lstrip("."))
                rule = f"{'DOMAIN-SUFFIX' if suffix else 'DOMAIN'},{value}"
            else:
                rule = _classical_rule(line)
        except CompileError:
            unsupported += 1
            continue
        if rule in seen:
            continue
        if len(rules) >= MAX_DOMAIN_RULES_PER_SOURCE:
            raise CompileError(
                f"domain source exceeds the {MAX_DOMAIN_RULES_PER_SOURCE}-rule limit")
        seen.add(rule)
        rules.append(rule)
    if not rules:
        raise CompileError("domain source contains no supported rules")
    return {
        "name": str(name)[:80],
        "url": str(source_url),
        "format": source_format,
        "rules": rules,
        "stats": {"supported_rules": len(rules), "unsupported_lines": unsupported},
    }


def local_domain_rules(config):
    """Compile server-only rules kept outside the repository and remote feeds."""
    items = config.get("local_domain_rules", []) if isinstance(config, dict) else []
    if not isinstance(items, list):
        raise CompileError("local_domain_rules must be a list")
    if len(items) > MAX_LOCAL_DOMAIN_RULES:
        raise CompileError(
            f"local_domain_rules exceeds the {MAX_LOCAL_DOMAIN_RULES}-rule limit")
    rules = []
    seen = set()
    for item in items:
        if not isinstance(item, str):
            raise CompileError("local_domain_rules entries must be strings")
        try:
            rule = _auto_domain_rule(item)
        except CompileError as exc:
            raise CompileError(f"invalid local domain rule: {item[:80]}") from exc
        if rule not in seen:
            seen.add(rule)
            rules.append(rule)
    return rules


def compile_domain_sources(config, fetcher=fetch_domain_text):
    items = _enabled_source_items(config, "domain_sources")
    sources = []
    failures = []
    rules = []
    seen = set()
    for batch in _fetched_source_batches(items, fetcher):
        for item, future in batch:
            name = str(item.get("name") or "unnamed")[:80]
            url = str(item.get("url") or "")
            try:
                source = parse_domain_source(
                    future.result(), name, url, item.get("format", "auto"))
            except Exception as exc:
                failures.append({"name": name, "error": str(exc)[:200]})
                continue
            sources.append({key: source[key] for key in ("name", "url", "format", "stats")})
            for rule in source["rules"]:
                if rule in seen:
                    continue
                if len(rules) >= MAX_DOMAIN_RULES_TOTAL:
                    raise CompileError(
                        f"compiled domain rules exceed the {MAX_DOMAIN_RULES_TOTAL}-rule limit")
                seen.add(rule)
                rules.append(rule)
    local_rules = local_domain_rules(config)
    for rule in local_rules:
        if rule in seen:
            continue
        if len(rules) >= MAX_DOMAIN_RULES_TOTAL:
            raise CompileError(
                f"compiled domain rules exceed the {MAX_DOMAIN_RULES_TOTAL}-rule limit")
        seen.add(rule)
        rules.append(rule)
    return {
        "rules": rules,
        "sources": sources,
        "failures": failures,
        "stats": {
            "domain_source_count": len(sources),
            "domain_failed_sources": len(failures),
            "domain_rule_count": len(rules),
            "domain_local_rule_count": len(local_rules),
            "domain_unsupported_lines": sum(
                source["stats"]["unsupported_lines"] for source in sources),
        },
    }


def split_domain_rules(rules):
    """Split rules into mihomo's optimized domain format and classical fallback."""
    domains = []
    classical = []
    seen_domains = set()
    seen_classical = set()
    for rule in rules:
        fields = str(rule).split(",")
        kind = fields[0]
        value = fields[1] if len(fields) > 1 else ""
        if kind == "DOMAIN":
            converted = value
        elif kind == "DOMAIN-SUFFIX":
            # Mihomo's domain text format uses "+." for suffix semantics that
            # include both the apex and its subdomains. A leading dot only
            # matches subdomains and silently misses a suffix rule when an app
            # calls the apex itself.
            converted = "+." + value
        elif kind == "DOMAIN-WILDCARD":
            converted = value
        else:
            if rule not in seen_classical:
                seen_classical.add(rule)
                classical.append(rule)
            continue
        if converted not in seen_domains:
            seen_domains.add(converted)
            domains.append(converted)
    return domains, classical


def atomic_write(path, payload, owner="pdg-wloc"):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o755, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".adblock-", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(payload, file, ensure_ascii=False, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temporary, 0o600)
        try:
            account = pwd.getpwnam(owner)
            os.chown(temporary, account.pw_uid, account.pw_gid)
        except KeyError:
            pass
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_write_provider(path, rules):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".adblock-provider-", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write("payload:\n")
            for rule in rules:
                file.write("  - " + json.dumps(rule, ensure_ascii=False) + "\n")
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_write_domain_mrs(path, domains, converter="mihomo"):
    if not domains:
        raise CompileError("no domain rules available for MRS conversion")
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    source_fd, source = tempfile.mkstemp(prefix=".adblock-domain-", dir=directory, text=True)
    target_fd, target = tempfile.mkstemp(prefix=".adblock-mrs-", dir=directory)
    os.close(target_fd)
    try:
        with os.fdopen(source_fd, "w", encoding="utf-8") as file:
            file.write("\n".join(domains) + "\n")
            file.flush()
            os.fsync(file.fileno())
        try:
            result = subprocess.run(
                [converter, "convert-ruleset", "domain", "text", source, target],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CompileError(f"MRS conversion failed: {exc}") from exc
        if result.returncode or not os.path.exists(target) or not os.path.getsize(target):
            detail = (result.stdout + result.stderr).decode("utf-8", "replace").strip()[-200:]
            raise CompileError("MRS conversion failed" + ((": " + detail) if detail else ""))
        os.chmod(target, 0o600)
        os.replace(target, path)
    finally:
        for temporary in (source, target):
            if os.path.exists(temporary):
                os.unlink(temporary)


def merge_source_defaults(path, defaults_path):
    with open(path, encoding="utf-8") as file:
        current = json.load(file)
    with open(defaults_path, encoding="utf-8") as file:
        defaults = json.load(file)
    if not isinstance(current, dict) or not isinstance(defaults, dict):
        raise CompileError("source configs must be JSON objects")
    changed = False
    for key in ("sources", "domain_sources", "script_conversions", "external_jq_pins"):
        if key not in current and key in defaults:
            current[key] = defaults[key]
            changed = True
    if not changed:
        return False
    stat = os.stat(path)
    directory = os.path.dirname(path) or "."
    fd, temporary = tempfile.mkstemp(prefix=".adblock-sources-", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(current, file, ensure_ascii=False, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temporary, stat.st_mode & 0o777)
        os.chown(temporary, stat.st_uid, stat.st_gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def pin_missing_modules(path, fetcher=fetch_text, cache_dir=DEFAULT_MODULE_CACHE):
    """Trust-on-first-use migration for legacy source entries without SHA256."""
    with open(path, encoding="utf-8") as file:
        config = json.load(file)
    if not isinstance(config, dict):
        raise CompileError("source config must be a JSON object")
    items = _enabled_source_items(config, "sources")
    missing = [item for item in items if not str(item.get("sha256") or "").strip()]
    for item in items:
        _module_digest(item, required=item not in missing)
    if not missing:
        return 0
    fetched = {}
    for batch in _fetched_source_batches(missing, fetcher):
        for item, future in batch:
            name = str(item.get("name") or "unnamed")[:80]
            url = str(item.get("url") or "")
            try:
                text = future.result()
                module = parse_module(text, name, url)
                if (not module["rules"] and not module["hosts"]
                        and not module["stats"].get("unported_scripts")
                        and not re.search(
                            r"(?mi)^\s*\[(?:rewrite|script|mitm|rule)\]\s*$", text)):
                    raise CompileError("URL does not contain a recognized Loon/Egern module")
                digest = hashlib.sha256(text.encode()).hexdigest()
                _write_module_cache(cache_dir, url, digest, text)
                fetched[id(item)] = digest
            except Exception as exc:
                raise CompileError(f"cannot initialize module pin for {name}: {exc}") from exc
    for item in missing:
        item["sha256"] = fetched[id(item)]

    stat = os.stat(path)
    directory = os.path.dirname(path) or "."
    fd, temporary = tempfile.mkstemp(prefix=".adblock-pins-", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(config, file, ensure_ascii=False, indent=2)
            file.write("\n")
            file.flush(); os.fsync(file.fileno())
        os.chmod(temporary, stat.st_mode & 0o777)
        os.chown(temporary, stat.st_uid, stat.st_gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return len(missing)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources", default=DEFAULT_SOURCES)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--domain-output", default=DEFAULT_DOMAIN_OUTPUT)
    parser.add_argument("--classical-output", default=DEFAULT_CLASSICAL_OUTPUT)
    parser.add_argument("--mihomo", default="mihomo")
    parser.add_argument("--merge-defaults")
    parser.add_argument("--merge-only", action="store_true")
    parser.add_argument("--module-cache", default=DEFAULT_MODULE_CACHE)
    parser.add_argument("--pin-missing-modules", action="store_true")
    parser.add_argument("--check-module-url")
    parser.add_argument("--check-domain-url")
    args = parser.parse_args()
    if args.check_module_url:
        parsed = urllib.parse.urlsplit(args.check_module_url)
        name = os.path.basename(parsed.path).rsplit(".", 1)[0] or parsed.hostname or "custom"
        text = fetch_text(args.check_module_url)
        module = parse_module(text, name, args.check_module_url)
        if not module["rules"] and not module["hosts"] and not module["stats"]["unported_scripts"]:
            raise SystemExit("URL does not contain a recognized Loon/Egern module")
        stats = dict(module["stats"])
        stats.update({
            "sha256": hashlib.sha256(text.encode()).hexdigest(),
            "host_count": len(module["hosts"]),
            "rule_count": len(module["rules"]),
        })
        print(json.dumps(stats, ensure_ascii=False, sort_keys=True))
        return
    if args.check_domain_url:
        parsed = urllib.parse.urlsplit(args.check_domain_url)
        name = os.path.basename(parsed.path).rsplit(".", 1)[0] or parsed.hostname or "custom"
        source = parse_domain_source(
            fetch_domain_text(args.check_domain_url), name, args.check_domain_url, "auto")
        domains, classical = split_domain_rules(source["rules"])
        stats = dict(source["stats"])
        stats.update({
            "domain_mrs_rule_count": len(domains),
            "domain_classical_rule_count": len(classical),
        })
        print(json.dumps(stats, ensure_ascii=False, sort_keys=True))
        return
    if args.merge_defaults:
        changed = merge_source_defaults(args.sources, args.merge_defaults)
        if args.merge_only:
            print("merged" if changed else "already complete")
            return
    elif args.merge_only:
        raise SystemExit("--merge-only requires --merge-defaults")
    if args.pin_missing_modules:
        count = pin_missing_modules(args.sources, cache_dir=args.module_cache)
        print(json.dumps({"pinned_modules": count}, sort_keys=True))
        return
    with open(args.sources, encoding="utf-8") as file:
        config = json.load(file)
    compiled = compile_sources(
        config, module_cache_dir=args.module_cache, require_module_pins=True)
    domain = compile_domain_sources(config)
    failures = compiled["failures"] + domain["failures"]
    if failures:
        count = len(failures)
        names = ", ".join(item["name"] for item in failures[:5])
        raise SystemExit(f"{count} adblock source(s) failed ({names}); previous cache kept")
    if compiled["rules"] and not compiled["hosts"] \
            and not compiled["stats"].get("declared_host_count"):
        raise SystemExit("MITM rewrites were compiled without any exact hosts")
    if config.get("domain_sources") and not domain["rules"]:
        raise SystemExit("no usable domain adblock rules were compiled")
    compiled["domain_sources"] = domain["sources"]
    compiled["domain_failures"] = domain["failures"]
    compiled["stats"].update(domain["stats"])
    domains, classical = split_domain_rules(domain["rules"])
    compiled["stats"]["domain_mrs_rule_count"] = len(domains)
    compiled["stats"]["domain_classical_rule_count"] = len(classical)
    if domains:
        atomic_write_domain_mrs(args.domain_output, domains, args.mihomo)
    atomic_write_provider(args.classical_output, classical)
    atomic_write(args.output, compiled)
    print(json.dumps(compiled["stats"], ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
