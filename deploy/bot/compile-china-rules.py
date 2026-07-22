#!/usr/bin/env python3
"""Compile the downloaded ChinaMax list into compact mihomo providers.

The upstream rules stay on the gateway.  Only this converter is shipped in the
repository, so deployments can refresh the data independently every day.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import pathlib
import re
import subprocess
import tempfile


DOMAIN_OUTPUT = "__pdg_china_domain.mrs"
IP_OUTPUT = "__pdg_china_ip.mrs"
CLASSICAL_OUTPUT = "__pdg_china_classical.yaml"


class CompileError(RuntimeError):
    pass


def _append_unique(items, seen, value):
    if value not in seen:
        seen.add(value)
        items.append(value)


def parse_rules(path):
    domains, cidrs, classical = [], [], []
    seen_domains, seen_cidrs, seen_classical = set(), set(), set()
    with open(path, encoding="utf-8", errors="ignore") as source:
        for raw in source:
            line = raw.strip()
            if not line or line.startswith(("#", ";")) or len(line) > 4096:
                continue
            parts = [part.strip() for part in line.split(",")]
            if len(parts) < 2:
                continue
            kind, value = parts[0].upper(), parts[1]
            if not value or any(char.isspace() for char in value):
                continue
            if kind == "DOMAIN":
                if len(value) <= 253:
                    _append_unique(domains, seen_domains, value.lower().rstrip("."))
            elif kind == "DOMAIN-SUFFIX":
                value = value.lower().strip(".")
                if value and len(value) <= 253:
                    _append_unique(domains, seen_domains, "+." + value)
            elif kind == "DOMAIN-WILDCARD":
                if len(value) <= 253 and re.fullmatch(r"[A-Za-z0-9.*?_-]+", value):
                    _append_unique(domains, seen_domains, value.lower())
            elif kind == "DOMAIN-KEYWORD":
                if len(value) <= 128:
                    _append_unique(classical, seen_classical, "DOMAIN-KEYWORD," + value)
            elif kind == "IP-CIDR":
                try:
                    network = str(ipaddress.ip_network(value, strict=False))
                except ValueError:
                    continue
                _append_unique(cidrs, seen_cidrs, network)
    return domains, cidrs, classical


def _convert(converter, behavior, values, target):
    source = target.with_suffix(target.suffix + ".txt")
    source.write_text("\n".join(values) + "\n", encoding="utf-8")
    try:
        result = subprocess.run(
            [converter, "convert-ruleset", behavior, "text", str(source), str(target)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CompileError(f"{behavior} MRS conversion failed: {exc}") from exc
    if result.returncode or not target.is_file() or not target.stat().st_size:
        detail = (result.stdout + result.stderr).decode("utf-8", "replace").strip()[-300:]
        raise CompileError(
            f"{behavior} MRS conversion failed" + (f": {detail}" if detail else "")
        )


def compile_rules(source, output_dir, converter, min_domains=1000, min_cidrs=100):
    domains, cidrs, classical = parse_rules(source)
    if len(domains) < min_domains:
        raise CompileError(f"ChinaMax domain rules too few: {len(domains)}")
    if len(cidrs) < min_cidrs:
        raise CompileError(f"ChinaMax IP rules too few: {len(cidrs)}")

    output_dir = pathlib.Path(output_dir)
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".pdg-china-", dir=output_dir) as temporary:
        staging = pathlib.Path(temporary)
        domain_target = staging / DOMAIN_OUTPUT
        ip_target = staging / IP_OUTPUT
        classical_target = staging / CLASSICAL_OUTPUT
        _convert(converter, "domain", domains, domain_target)
        _convert(converter, "ipcidr", cidrs, ip_target)
        with classical_target.open("w", encoding="utf-8") as output:
            output.write("payload:\n")
            for rule in classical:
                output.write("  - " + json.dumps(rule, ensure_ascii=False) + "\n")
            output.flush()
            os.fsync(output.fileno())
        for staged, name in (
                (domain_target, DOMAIN_OUTPUT),
                (ip_target, IP_OUTPUT),
                (classical_target, CLASSICAL_OUTPUT)):
            os.chmod(staged, 0o600)
            os.replace(staged, output_dir / name)
    return {"domains": len(domains), "ipv4_cidrs": len(cidrs), "classical": len(classical)}


def main():
    parser = argparse.ArgumentParser(description="Compile ChinaMax for mihomo")
    parser.add_argument("source", help="downloaded ChinaMax.list")
    parser.add_argument("output_dir", help="mihomo rule-provider directory")
    parser.add_argument("--converter", default="mihomo", help="mihomo binary")
    parser.add_argument("--min-domains", type=int, default=1000)
    parser.add_argument("--min-cidrs", type=int, default=100)
    args = parser.parse_args()
    try:
        counts = compile_rules(
            args.source, args.output_dir, args.converter,
            max(0, args.min_domains), max(0, args.min_cidrs),
        )
    except CompileError as exc:
        parser.exit(1, f"[x] {exc}\n")
    print("ChinaMax mihomo providers: " + " ".join(f"{key}={value}" for key, value in counts.items()))


if __name__ == "__main__":
    main()
