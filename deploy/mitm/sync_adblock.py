#!/usr/bin/env python3
"""Compile safe declarative rewrites from allowlisted Loon/Egern modules."""
from __future__ import annotations

import argparse
import base64
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

DEFAULT_SOURCES = "/etc/privdns-gateway/adblock-sources.json"
DEFAULT_OUTPUT = "/var/lib/pdg-wloc/adblock-rules.json"
DEFAULT_DOMAIN_OUTPUT = "/etc/mihomo/rs/__pdg_adblock_reject.mrs"
DEFAULT_CLASSICAL_OUTPUT = "/etc/mihomo/rs/__pdg_adblock_reject_classical.yaml"
USER_AGENT = "Egern/1.22.0 CFNetwork/1498.700.2 Darwin/23.6.0"
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_DOMAIN_SOURCE_BYTES = 16 * 1024 * 1024
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
DOMAIN_TOKEN_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_.-]{0,251}[a-z0-9_])?$"
)
CLASSICAL_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6"}


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


def _domain_token(value):
    value = str(value).strip().lower().rstrip(".")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise CompileError("invalid internationalized domain") from exc
    if not DOMAIN_TOKEN_RE.fullmatch(value) or ".." in value:
        raise CompileError("invalid domain token")
    return value


def _classical_rule(line):
    fields = [field.strip() for field in str(line).split(",")]
    if len(fields) < 2 or fields[0].upper() not in CLASSICAL_TYPES:
        raise CompileError("unsupported classical rule")
    kind = fields[0].upper()
    value = fields[1]
    if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
        value = _domain_token(value.lstrip("+."))
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


def parse_domain_source(text, name, source_url="", source_format="classical"):
    source_format = str(source_format).strip().lower()
    if source_format not in {"classical", "domain-set"}:
        raise CompileError(f"unsupported domain source format {source_format}")
    rules = []
    unsupported = 0
    for raw in str(text).splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";", "!", "//")):
            continue
        try:
            if source_format == "domain-set":
                suffix = line.startswith((".", "+."))
                value = _domain_token(line[2:] if line.startswith("+.") else line.lstrip("."))
                rule = f"{'DOMAIN-SUFFIX' if suffix else 'DOMAIN'},{value}"
            else:
                rule = _classical_rule(line)
        except CompileError:
            unsupported += 1
            continue
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


def compile_domain_sources(config, fetcher=fetch_domain_text):
    items = config.get("domain_sources", []) if isinstance(config, dict) else []
    if not isinstance(items, list):
        raise CompileError("domain_sources must be a list")
    sources = []
    failures = []
    rules = []
    seen = set()
    for item in items:
        if not isinstance(item, dict) or not item.get("enabled", True):
            continue
        name = str(item.get("name") or "unnamed")[:80]
        url = str(item.get("url") or "")
        try:
            source = parse_domain_source(
                fetcher(url), name, url, item.get("format", "classical"))
        except Exception as exc:
            failures.append({"name": name, "error": str(exc)[:200]})
            continue
        sources.append({key: source[key] for key in ("name", "url", "format", "stats")})
        for rule in source["rules"]:
            if rule not in seen:
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
            converted = "." + value
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
    for key in ("sources", "domain_sources"):
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources", default=DEFAULT_SOURCES)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--domain-output", default=DEFAULT_DOMAIN_OUTPUT)
    parser.add_argument("--classical-output", default=DEFAULT_CLASSICAL_OUTPUT)
    parser.add_argument("--mihomo", default="mihomo")
    parser.add_argument("--merge-defaults")
    parser.add_argument("--merge-only", action="store_true")
    parser.add_argument("--check-module-url")
    args = parser.parse_args()
    if args.check_module_url:
        parsed = urllib.parse.urlsplit(args.check_module_url)
        name = os.path.basename(parsed.path).rsplit(".", 1)[0] or parsed.hostname or "custom"
        module = parse_module(fetch_text(args.check_module_url), name, args.check_module_url)
        if not module["rules"] and not module["hosts"] and not module["stats"]["unported_scripts"]:
            raise SystemExit("URL does not contain a recognized Loon/Egern module")
        print(json.dumps(module["stats"], ensure_ascii=False, sort_keys=True))
        return
    if args.merge_defaults:
        changed = merge_source_defaults(args.sources, args.merge_defaults)
        if args.merge_only:
            print("merged" if changed else "already complete")
            return
    elif args.merge_only:
        raise SystemExit("--merge-only requires --merge-defaults")
    with open(args.sources, encoding="utf-8") as file:
        config = json.load(file)
    compiled = compile_sources(config)
    domain = compile_domain_sources(config)
    failures = compiled["failures"] + domain["failures"]
    if failures:
        count = len(failures)
        names = ", ".join(item["name"] for item in failures[:5])
        raise SystemExit(f"{count} adblock source(s) failed ({names}); previous cache kept")
    if compiled["rules"] and not compiled["hosts"]:
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
