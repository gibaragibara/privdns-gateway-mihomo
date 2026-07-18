#!/usr/bin/env python3
"""Compile safe declarative rewrites from allowlisted Loon/Egern modules."""
from __future__ import annotations

import argparse
import base64
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

DEFAULT_SOURCES = "/etc/privdns-gateway/adblock-sources.json"
DEFAULT_OUTPUT = "/var/lib/pdg-wloc/adblock-rules.json"
USER_AGENT = "Egern/1.22.0 CFNetwork/1498.700.2 Darwin/23.6.0"
MAX_SOURCE_BYTES = 2 * 1024 * 1024
SUPPORTED_ACTIONS = {
    "reject", "reject-200", "reject-dict", "reject-img",
    "mock-response-body", "response-body-json-del",
    "response-body-json-jq", "response-body-json-replace",
    "response-body-replace-regex", "response-header-add",
}
HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


class CompileError(ValueError):
    pass


def fetch_text(url, timeout=25):
    parsed = urllib.parse.urlsplit(str(url))
    if parsed.scheme != "https" or not parsed.hostname or parsed.username:
        raise CompileError("module source must be an HTTPS URL without credentials")
    curl = shutil.which("curl")
    if not curl:
        raise CompileError("curl is required to download protected module sources")
    try:
        result = subprocess.run(
            [curl, "-fsSL", "--max-time", str(int(timeout)), "--max-filesize",
             str(MAX_SOURCE_BYTES), "-A", USER_AGENT, "-H", "Accept: */*", str(url)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 5, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CompileError("module download timed out") from exc
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace").strip()[-160:]
        raise CompileError("module download failed" + ((": " + detail) if detail else ""))
    data = result.stdout
    if len(data) > MAX_SOURCE_BYTES:
        raise CompileError("module exceeds 2 MiB")
    return data.decode("utf-8-sig")


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
        if len(values[0]) > 2000 or re.search(
                r"(?:\$ENV\b|\b(?:debug|env|include|import|input|inputs|module)\b)", values[0]):
            raise CompileError("jq program uses a blocked capability")
        return {"program": values[0]}
    if action == "response-body-replace-regex":
        values = _tokens(arguments)
        if len(values) != 2:
            raise CompileError("response-body-replace-regex requires pattern/replacement")
        re.compile(values[0])
        return {"pattern": values[0], "replacement": values[1]}
    raise CompileError(f"unsupported action {action}")


def _module_hosts(lines):
    hosts = set()
    skipped = 0
    for line in lines:
        if not line.startswith("hostname="):
            continue
        for item in line.split("=", 1)[1].split(","):
            host = item.strip().lower().lstrip("-")
            if not host:
                continue
            if any(char in host for char in "*?[]"):
                skipped += 1
                continue
            if HOST_RE.fullmatch(host):
                hosts.add(host)
            else:
                skipped += 1
    return hosts, skipped


def parse_module(text, name, source_url=""):
    sections = {}
    section = None
    scripts = 0
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
        if section == "Script" and line.startswith(("http-request ", "http-response ")):
            scripts += 1

    hosts, skipped_hosts = _module_hosts(sections.get("MitM", []))
    rules = []
    unsupported = Counter()
    invalid = 0
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

    return {
        "name": str(name)[:80],
        "url": str(source_url),
        "hosts": sorted(hosts),
        "rules": rules,
        "stats": {
            "supported_rewrites": len(rules),
            "unsupported_rewrites": sum(unsupported.values()) + invalid,
            "unsupported_actions": dict(sorted(unsupported.items())),
            "unported_scripts": scripts,
            "skipped_hosts": skipped_hosts,
        },
    }


def compile_sources(config, fetcher=fetch_text):
    items = config.get("sources", []) if isinstance(config, dict) else []
    if not isinstance(items, list):
        raise CompileError("sources must be a list")
    compiled_sources = []
    rules = []
    hosts = set()
    seen_rules = set()
    failures = []
    for item in items:
        if not isinstance(item, dict) or not item.get("enabled", True):
            continue
        name = str(item.get("name") or "unnamed")[:80]
        url = str(item.get("url") or "")
        try:
            module = parse_module(fetcher(url), name, url)
        except Exception as exc:  # one unavailable source must not discard the others
            failures.append({"name": name, "error": str(exc)[:200]})
            continue
        compiled_sources.append({key: module[key] for key in ("name", "url", "stats")})
        if not module["rules"]:
            continue
        hosts.update(module["hosts"])
        for rule in module["rules"]:
            key = json.dumps(rule, ensure_ascii=False, sort_keys=True)
            if key not in seen_rules:
                seen_rules.add(key)
                rules.append(rule)
    stats = {
        "source_count": len(compiled_sources),
        "failed_sources": len(failures),
        "host_count": len(hosts),
        "rule_count": len(rules),
        "unported_scripts": sum(s["stats"]["unported_scripts"] for s in compiled_sources),
        "unsupported_rewrites": sum(s["stats"]["unsupported_rewrites"] for s in compiled_sources),
    }
    return {
        "version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "hosts": sorted(hosts),
        "rules": rules,
        "sources": compiled_sources,
        "failures": failures,
        "stats": stats,
    }


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources", default=DEFAULT_SOURCES)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    with open(args.sources, encoding="utf-8") as file:
        config = json.load(file)
    compiled = compile_sources(config)
    if compiled["failures"]:
        count = len(compiled["failures"])
        names = ", ".join(item["name"] for item in compiled["failures"][:5])
        raise SystemExit(f"{count} module source(s) failed ({names}); previous cache kept")
    if not compiled["rules"] or not compiled["hosts"]:
        raise SystemExit("no usable adblock rules or exact MITM hosts were compiled")
    atomic_write(args.output, compiled)
    print(json.dumps(compiled["stats"], ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
