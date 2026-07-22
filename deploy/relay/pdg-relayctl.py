#!/usr/bin/env python3
"""PrivDNS Apple Network Relay control plane.

The relay is intentionally separate from the legacy 5GPN TPROXY listener.  Envoy
runs as ``pdg-relay`` and only that UID is returned to mihomo through a dedicated
nftables output TPROXY rule.  This keeps the existing policy plane (outbounds,
REJECT, MITM and WLOC) while making the iOS Relay payload full-device.
"""
import argparse
import grp
import hashlib
import ipaddress
import json
import os
import pathlib
import plistlib
import pwd
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid


SERVICE = "pdg-relay"
CONFIG = pathlib.Path("/etc/privdns-gateway/relay.json")
STATE = pathlib.Path("/etc/mihomo/state.json")
DOT_DOMAIN = pathlib.Path("/opt/pdg-bot/dot-domain")
CERT = pathlib.Path("/etc/mosdns/certs/fullchain.pem")
KEY = pathlib.Path("/etc/mosdns/certs/privkey.pem")
RELAY_DIR = pathlib.Path("/etc/pdg-relay")
TLS_DIR = RELAY_DIR / "tls"
ENVOY_CONFIG = RELAY_DIR / "envoy.yaml"
ENVOY = pathlib.Path("/opt/pdg-relay/bin/envoy")
MIHOMO_CONFIG = pathlib.Path("/etc/mihomo/config.yaml")
CHINA_PROVIDERS = (
    pathlib.Path("/etc/mihomo/rs/__pdg_china_domain.mrs"),
    pathlib.Path("/etc/mihomo/rs/__pdg_china_ip.mrs"),
    pathlib.Path("/etc/mihomo/rs/__pdg_china_classical.yaml"),
)
SERVICE_USER = "pdg-relay"
DEFAULT_PORT = 20443
ADMIN_PORT = 9902

# Pinned to the audited Envoy release used by the original 5gpn-relay project.
ENVOY_VERSION = "1.39.0"
ENVOY_SHA256 = {
    "x86_64": "4409dadc87931d8f8676314cbd83071cb65125fb4feac3f6335800580dfa9218",
    "aarch_64": "ee53a4f5375566f15944dc9cb03afb1fc228df38f61737c677f139213215afcf",
}


class RelayError(RuntimeError):
    pass


def _run(args, *, check=True, timeout=180):
    try:
        result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    except OSError as exc:
        raise RelayError(f"无法执行 {' '.join(args)}: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RelayError(f"命令超时: {' '.join(args)}") from exc
    if check and result.returncode:
        detail = (result.stdout + result.stderr).strip()[-800:]
        raise RelayError(f"命令失败 ({' '.join(args)}): {detail or result.returncode}")
    return result


def _atomic_write(path, content, mode, *, uid=None, gid=None):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".pdg-relay-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temporary, mode)
        if uid is not None or gid is not None:
            os.chown(temporary, -1 if uid is None else uid, -1 if gid is None else gid)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _valid_host(value):
    value = str(value or "").strip().lower().rstrip(".")
    if len(value) > 253 or not value or "." not in value:
        return ""
    labels = value.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        return ""
    return value


def _valid_port(value):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return 0
    return value if 1024 <= value <= 65535 else 0


def _nonempty_file(path):
    try:
        return pathlib.Path(path).is_file() and pathlib.Path(path).stat().st_size > 0
    except OSError:
        return False


def _default_config():
    return {
        "enabled": False,
        "host": "",
        "listen_port": DEFAULT_PORT,
        "token": "",
        "relay_uuid": "",
        "payload_uuid": "",
        "profile_uuid": "",
        "created_at": None,
    }


def _load_config(required=False):
    if not CONFIG.exists():
        if required:
            raise RelayError("Relay 尚未配置，请先运行 pdg relay enable")
        return _default_config()
    try:
        raw = json.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RelayError(f"Relay 配置损坏，拒绝覆盖: {exc}") from exc
    if not isinstance(raw, dict):
        raise RelayError("Relay 配置不是对象，拒绝覆盖")
    config = _default_config()
    config.update(raw)
    config["enabled"] = bool(config.get("enabled"))
    config["host"] = _valid_host(config.get("host"))
    config["listen_port"] = _valid_port(config.get("listen_port")) or DEFAULT_PORT
    return config


def _save_config(config):
    CONFIG.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(CONFIG.parent, 0o700)
    _atomic_write(CONFIG, (json.dumps(config, ensure_ascii=False, indent=2) + "\n").encode(), 0o600)


def _uuid(value):
    try:
        return str(uuid.UUID(str(value))).upper()
    except (ValueError, TypeError, AttributeError):
        return ""


def _server_ip():
    try:
        config = json.loads(STATE.read_text(encoding="utf-8"))
        for rule in config.get("route", {}).get("rules", []):
            if rule.get("action") != "reject":
                continue
            for cidr in rule.get("ip_cidr", []):
                address = str(cidr).split("/", 1)[0]
                parsed = ipaddress.ip_address(address)
                if parsed.version == 4 and not parsed.is_loopback:
                    return str(parsed)
    except Exception:  # noqa: BLE001
        pass
    raise RelayError("读不到本机公网 IP(/etc/mihomo/state.json)")


def _certificate_host():
    host = _valid_host(DOT_DOMAIN.read_text(encoding="utf-8").strip()) if DOT_DOMAIN.exists() else ""
    if host:
        return host
    if not CERT.exists():
        return ""
    result = _run(["openssl", "x509", "-in", str(CERT), "-noout", "-subject"], check=False)
    match = re.search(r"CN\s*=\s*([A-Za-z0-9.-]+)", result.stdout + result.stderr)
    return _valid_host(match.group(1)) if match else ""


def _ensure_service_user():
    try:
        account = pwd.getpwnam(SERVICE_USER)
    except KeyError:
        _run(["useradd", "--system", "--user-group", "--no-create-home",
              "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", SERVICE_USER])
        account = pwd.getpwnam(SERVICE_USER)
    try:
        service_group = grp.getgrnam(SERVICE_USER)
    except KeyError:
        _run(["groupadd", "--system", SERVICE_USER])
        service_group = grp.getgrnam(SERVICE_USER)
    if account.pw_gid != service_group.gr_gid:
        _run(["usermod", "--gid", SERVICE_USER, SERVICE_USER])
        account = pwd.getpwnam(SERVICE_USER)
    return account


def _ensure_layout():
    account = _ensure_service_user()
    RELAY_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    TLS_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    pathlib.Path("/opt/pdg-relay/bin").mkdir(mode=0o755, parents=True, exist_ok=True)
    os.chmod(RELAY_DIR, 0o750)
    os.chmod(TLS_DIR, 0o750)
    os.chown(RELAY_DIR, 0, account.pw_gid)
    os.chown(TLS_DIR, 0, account.pw_gid)
    return account


def _assert_certificate(host):
    if not CERT.is_file() or not KEY.is_file():
        raise RelayError("缺少现有 DoT TLS 证书或私钥")
    _run(["openssl", "x509", "-checkend", "0", "-noout", "-in", str(CERT)])
    checked = _run(["openssl", "x509", "-checkhost", host, "-noout", "-in", str(CERT)], check=False)
    if checked.returncode:
        raise RelayError(f"现有 DoT 证书不覆盖 Relay 域名 {host}")
    certificate_key = _run(["openssl", "x509", "-in", str(CERT), "-noout", "-pubkey"]).stdout.strip()
    private_key = _run(["openssl", "pkey", "-in", str(KEY), "-pubout"]).stdout.strip()
    if not certificate_key or certificate_key != private_key:
        raise RelayError("Relay TLS 证书与私钥不匹配")


def sync_certificate(config=None):
    config = config or _load_config(required=True)
    host = _valid_host(config.get("host"))
    if not host:
        raise RelayError("Relay 域名为空")
    _assert_certificate(host)
    account = _ensure_layout()
    _atomic_write(TLS_DIR / "fullchain.pem", CERT.read_bytes(), 0o644, uid=0, gid=account.pw_gid)
    _atomic_write(TLS_DIR / "privkey.pem", KEY.read_bytes(), 0o640, uid=0, gid=account.pw_gid)


def _envoy_asset():
    machine = os.uname().machine.lower()
    aliases = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "aarch_64", "aarch64": "aarch_64"}
    machine = aliases.get(machine, machine)
    if machine not in ENVOY_SHA256:
        raise RelayError(f"不支持的 Envoy 架构: {machine}")
    asset = "x86_64" if machine == "x86_64" else "aarch_64"
    url = f"https://github.com/envoyproxy/envoy/releases/download/v{ENVOY_VERSION}/envoy-{ENVOY_VERSION}-linux-{asset}"
    return url, ENVOY_SHA256[machine]


def ensure_envoy():
    if ENVOY.is_file() and os.access(ENVOY, os.X_OK):
        result = _run([str(ENVOY), "--version"], check=False)
        existing = result.stdout + result.stderr
        if ENVOY_VERSION in existing:
            return
    url, expected = _envoy_asset()
    temporary = None
    try:
        ENVOY.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        # Stage beside the destination so the final atomic rename also works
        # when /tmp and /opt are different filesystems.
        fd, temporary = tempfile.mkstemp(prefix=".pdg-envoy-", dir=ENVOY.parent)
        with os.fdopen(fd, "wb") as output:
            request = urllib.request.Request(url, headers={"User-Agent": "PrivDNS-Gateway/relay"})
            with urllib.request.urlopen(request, timeout=120) as response:
                shutil.copyfileobj(response, output)
            output.flush()
            os.fsync(output.fileno())
        actual = hashlib.sha256(pathlib.Path(temporary).read_bytes()).hexdigest()
        if not secrets.compare_digest(actual, expected):
            raise RelayError("Envoy SHA256 校验失败，拒绝安装")
        pathlib.Path("/opt/pdg-relay/bin").mkdir(mode=0o755, parents=True, exist_ok=True)
        os.chmod(temporary, 0o755)
        os.replace(temporary, ENVOY)
        temporary = None
    except RelayError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise RelayError(f"下载 Envoy 失败: {exc}") from exc
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    result = _run([str(ENVOY), "--version"], check=False)
    version = result.stdout + result.stderr
    if ENVOY_VERSION not in version:
        raise RelayError("Envoy 二进制版本校验失败")


def _require_complete(config):
    host = _valid_host(config.get("host"))
    token = str(config.get("token") or "").strip().lower()
    port = _valid_port(config.get("listen_port"))
    relay_uuid = _uuid(config.get("relay_uuid"))
    payload_uuid = _uuid(config.get("payload_uuid"))
    profile_uuid = _uuid(config.get("profile_uuid"))
    if not host or not port or not re.fullmatch(r"[0-9a-f]{64}", token):
        raise RelayError("Relay 配置不完整")
    if not relay_uuid or not payload_uuid or not profile_uuid:
        raise RelayError("Relay UUID 配置不完整")
    config.update({"host": host, "token": token, "listen_port": port,
                   "relay_uuid": relay_uuid, "payload_uuid": payload_uuid,
                   "profile_uuid": profile_uuid})
    return config


def _assert_china_direct():
    missing = [str(path) for path in CHINA_PROVIDERS if not _nonempty_file(path)]
    try:
        rendered = MIHOMO_CONFIG.read_text(encoding="utf-8")
    except OSError:
        rendered = ""
    markers = (
        "RULE-SET,__pdg_china_domain,DIRECT",
        "RULE-SET,__pdg_china_ip,DIRECT,no-resolve",
    )
    if missing or not all(marker in rendered for marker in markers):
        raise RelayError(
            "ChinaMax 直连 MRS 尚未加载；请先运行 "
            "bash /opt/pdg-bot/update-rules.sh，避免国内流量落入默认国际出口"
        )


def render_envoy_text(config):
    config = _require_complete(dict(config))
    token, port = config["token"], config["listen_port"]
    return f'''# Generated by pdg-relayctl. Do not edit by hand.
admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: {ADMIN_PORT}

overload_manager:
  resource_monitors:
  - name: envoy.resource_monitors.global_downstream_max_connections
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.resource_monitors.downstream_connections.v3.DownstreamConnectionsConfig
      max_active_downstream_connections: 1024

static_resources:
  listeners:
  - name: relay_http2
    address:
      socket_address:
        protocol: TCP
        address: 0.0.0.0
        port_value: {port}
    filter_chains:
    - transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            alpn_protocols: [h2]
            tls_params:
              tls_minimum_protocol_version: TLSv1_2
            tls_certificates:
            - certificate_chain:
                filename: {TLS_DIR}/fullchain.pem
              private_key:
                filename: {TLS_DIR}/privkey.pem
      filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          codec_type: HTTP2
          stat_prefix: relay_http2
          access_log:
          - name: envoy.access_loggers.stderr
            filter:
              status_code_filter:
                comparison:
                  op: GE
                  value:
                    default_value: 400
                    runtime_key: relay.access_log.min_status_code
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StderrAccessLog
              log_format:
                text_format_source:
                  inline_string: "[relay-error] %START_TIME% client=%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT% method=%REQ(:METHOD)% authority=%REQ(:AUTHORITY)% code=%RESPONSE_CODE% flags=%RESPONSE_FLAGS% upstream=%UPSTREAM_HOST% transport=%UPSTREAM_TRANSPORT_FAILURE_REASON% duration_ms=%DURATION%\\n"
          # APNs and other push channels are intentionally long-lived and quiet.
          stream_idle_timeout: 0s
          request_timeout: 0s
          route_config:
            name: relay_routes_http2
            virtual_hosts:
            - name: relay
              domains: ["*"]
              routes:
              - match:
                  connect_matcher: {{}}
                route:
                  cluster: dynamic_forward_proxy
                  timeout: 0s
                  upgrade_configs:
                  - upgrade_type: CONNECT
                    connect_config: {{}}
                  - upgrade_type: CONNECT-UDP
                    connect_config: {{}}
          http_filters:
          - name: envoy.filters.http.rbac
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC
              rules:
                action: ALLOW
                policies:
                  relay_token:
                    permissions:
                    - header:
                        name: x-relay-token
                        string_match:
                          exact: "{token}"
                    principals:
                    - any: true
          - name: envoy.filters.http.dynamic_forward_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig
              dns_cache_config:
                name: relay_dns_cache
                dns_lookup_family: V4_PREFERRED
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
          http2_protocol_options:
            allow_connect: true

  clusters:
  - name: dynamic_forward_proxy
    connect_timeout: 10s
    lb_policy: CLUSTER_PROVIDED
    cluster_type:
      name: envoy.clusters.dynamic_forward_proxy
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig
        dns_cache_config:
          name: relay_dns_cache
          dns_lookup_family: V4_PREFERRED
'''


def render(config=None):
    config = _require_complete(config or _load_config(required=True))
    _atomic_write(ENVOY_CONFIG, render_envoy_text(config).encode(), 0o640, uid=0,
                  gid=_ensure_service_user().pw_gid)


def validate(config=None, *, require_binary=True):
    config = _require_complete(config or _load_config(required=True))
    _assert_china_direct()
    _assert_certificate(config["host"])
    if not ENVOY.is_file() or not os.access(ENVOY, os.X_OK):
        if require_binary:
            raise RelayError("Envoy 尚未安装")
        return
    render(config)
    _run([str(ENVOY), "--mode", "validate", "-c", str(ENVOY_CONFIG)], timeout=90)
    helper = pathlib.Path("/usr/local/bin/pdg-relay-tproxy.sh")
    if helper.exists():
        _run([str(helper), "check"], timeout=30)


def _prepare_config(host=None, port=None):
    config = _load_config()
    selected_host = _valid_host(host) if host else _valid_host(config.get("host"))
    selected_host = selected_host or _certificate_host()
    if not selected_host:
        raise RelayError("读不到 Relay 域名；请使用 --host 指定一个现有 TLS 证书覆盖的域名")
    selected_port = _valid_port(port) if port is not None else _valid_port(config.get("listen_port"))
    if not selected_port:
        raise RelayError("Relay 端口必须为 1024-65535")
    config["host"] = selected_host
    config["listen_port"] = selected_port
    config["token"] = str(config.get("token") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", config["token"]):
        config["token"] = secrets.token_hex(32)
    for key in ("relay_uuid", "payload_uuid", "profile_uuid"):
        if not _uuid(config.get(key)):
            config[key] = str(uuid.uuid4()).upper()
    config["created_at"] = config.get("created_at") or time.strftime("%Y-%m-%dT%H:%M:%S%z")
    return _require_complete(config)


def _service_active():
    return _run(["systemctl", "is-active", SERVICE], check=False).stdout.strip() == "active"


def _wait_active(timeout=20):
    for _ in range(timeout * 2):
        if _service_active():
            return True
        time.sleep(0.5)
    return False


def enable(args):
    previous_exists = CONFIG.exists()
    previous_config = _load_config()
    previous_bytes = CONFIG.read_bytes() if previous_exists else None
    previous_envoy = ENVOY_CONFIG.read_bytes() if ENVOY_CONFIG.exists() else None
    was_active = bool(previous_config.get("enabled")) and _service_active()
    config = _prepare_config(args.host, args.port)
    config["enabled"] = True
    try:
        _assert_certificate(config["host"])
        _ensure_layout()
        ensure_envoy()
        sync_certificate(config)
        render(config)
        validate(config)
        _save_config(config)
        _run(["systemctl", "daemon-reload"])
        _run(["systemctl", "enable", SERVICE], timeout=60)
        _run(["systemctl", "restart", SERVICE], timeout=60)
        if not _wait_active():
            log = _run(["journalctl", "-u", SERVICE, "-n", "40", "--no-pager"], check=False).stdout[-1200:]
            raise RelayError("Relay 服务未能稳定启动\n" + log)
    except Exception:
        if previous_bytes is not None:
            _atomic_write(CONFIG, previous_bytes, 0o600)
        else:
            config["enabled"] = False
            _save_config(config)
        if previous_envoy is None:
            ENVOY_CONFIG.unlink(missing_ok=True)
        else:
            _atomic_write(ENVOY_CONFIG, previous_envoy, 0o640, uid=0,
                          gid=_ensure_service_user().pw_gid)
        if was_active:
            _run(["systemctl", "restart", SERVICE], check=False, timeout=60)
        else:
            _run(["systemctl", "disable", "--now", SERVICE], check=False, timeout=60)
        raise
    print(f"Relay 已启用: https://{config['host']}:{config['listen_port']}/")


def disable(_args):
    _run(["systemctl", "disable", "--now", SERVICE], check=False, timeout=60)
    helper = pathlib.Path("/usr/local/bin/pdg-relay-tproxy.sh")
    if helper.exists():
        _run([str(helper), "down"], check=False)
    try:
        config = _load_config()
    except RelayError as exc:
        print(f"Relay 已停止并清理专用路由；损坏的配置已保留供排查: {exc}")
        return
    config["enabled"] = False
    _save_config(config)
    print("Relay 已关闭；旧 DoT/TPROXY 链路未改动。")


def rotate_token(_args):
    config = _require_complete(_load_config(required=True))
    old = dict(config)
    previous_envoy = ENVOY_CONFIG.read_bytes() if ENVOY_CONFIG.exists() else None
    config["token"] = secrets.token_hex(32)
    try:
        _save_config(config)
        render(config)
        validate(config)
        if config.get("enabled"):
            _run(["systemctl", "restart", SERVICE], timeout=60)
            if not _wait_active():
                raise RelayError("新 token 的 Relay 未能重启")
    except Exception:
        _save_config(old)
        if previous_envoy is None:
            ENVOY_CONFIG.unlink(missing_ok=True)
        else:
            _atomic_write(ENVOY_CONFIG, previous_envoy, 0o640, uid=0, gid=_ensure_service_user().pw_gid)
        if old.get("enabled"):
            _run(["systemctl", "restart", SERVICE], check=False, timeout=60)
        raise
    print("Relay token 已轮换；请重新下发所有 iOS Relay 描述文件。")


def profile_bytes(config=None):
    config = _require_complete(config or _load_config(required=True))
    endpoint = f"https://{config['host']}:{config['listen_port']}/"
    relay_payload = {
        "PayloadDescription": "PrivDNS Gateway 全设备 Network Relay",
        "PayloadDisplayName": "PrivDNS 全量 Relay",
        "PayloadIdentifier": "com.privdns.gateway.relay.payload",
        "PayloadType": "com.apple.relay.managed",
        "PayloadUUID": config["payload_uuid"],
        "PayloadVersion": 1,
        "Relays": [{
            "HTTP2RelayURL": endpoint,
            "AdditionalHTTPHeaderFields": {"X-Relay-Token": config["token"]},
        }],
        # Omit MatchDomains deliberately: Apple then routes all domains through the relay.
        "ExcludedDomains": [config["host"]],
        "RelayUUID": config["relay_uuid"],
    }
    profile = {
        "PayloadContent": [relay_payload],
        "PayloadDescription": "PrivDNS Gateway 全设备 Relay 配置（可随时移除）",
        "PayloadDisplayName": "PrivDNS 全量 Relay",
        "PayloadIdentifier": "com.privdns.gateway.relay.profile",
        "PayloadOrganization": "PrivDNS Gateway",
        "PayloadRemovalDisallowed": False,
        "PayloadScope": "System",
        "PayloadType": "Configuration",
        "PayloadUUID": config["profile_uuid"],
        "PayloadVersion": 1,
    }
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML, sort_keys=False)


def profile(args):
    config = _require_complete(_load_config(required=True))
    if not config.get("enabled"):
        raise RelayError("Relay 未启用，拒绝下发不可用的描述文件")
    if not _service_active():
        raise RelayError("Relay 服务未运行，拒绝下发不可用的描述文件")
    _assert_china_direct()
    content = profile_bytes(config)
    if args.output:
        path = pathlib.Path(args.output)
        _atomic_write(path, content, 0o600)
        print(path)
    else:
        sys.stdout.buffer.write(content)


def status(args):
    configured = CONFIG.exists()
    try:
        config = _load_config(required=False)
        complete = bool(config.get("host") and config.get("token"))
        endpoint = f"https://{config['host']}:{config['listen_port']}/" if complete else ""
        service_state = _run(["systemctl", "is-active", SERVICE], check=False).stdout.strip() or "unknown"
        try:
            _assert_china_direct()
            china_direct_ready = True
        except RelayError:
            china_direct_ready = False
        payload = {
            "configured": configured,
            "enabled": bool(config.get("enabled")),
            "service": service_state,
            "host": config.get("host") or "",
            "listen_port": config.get("listen_port") if complete else None,
            "endpoint": endpoint,
            "china_direct_ready": china_direct_ready,
            "profile_ready": complete and bool(config.get("enabled"))
                and service_state == "active" and china_direct_ready,
            "server_ip": _server_ip() if configured else "",
        }
    except RelayError as exc:
        payload = {"configured": configured, "error": str(exc), "service": "unknown"}
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    else:
        if payload.get("error"):
            print("Relay 配置异常: " + payload["error"])
        else:
            print("Relay: " + ("已启用" if payload["enabled"] else "已关闭"))
            print("服务: " + payload["service"])
            print("入口: " + (payload["endpoint"] or "未配置"))
            print("描述文件: " + ("可生成" if payload["profile_ready"] else "不可生成"))


def main():
    parser = argparse.ArgumentParser(description="PrivDNS Apple Network Relay 控制器")
    sub = parser.add_subparsers(dest="command", required=True)
    enable_parser = sub.add_parser("enable", help="配置并启用 Relay")
    enable_parser.add_argument("--host", help="现有 TLS 证书覆盖的 Relay 域名")
    enable_parser.add_argument("--port", type=int, help=f"监听端口（默认 {DEFAULT_PORT}）")
    sub.add_parser("disable", help="停止 Relay，保留旧 5GPN 链路")
    sub.add_parser("rotate-token", help="轮换 Relay token")
    sub.add_parser("sync-cert", help="同步 DoT TLS 证书到 Relay")
    sub.add_parser("render", help="渲染 Envoy 配置")
    sub.add_parser("validate", help="校验 Relay 配置")
    profile_parser = sub.add_parser("profile", help="生成全量 iOS Relay 描述文件")
    profile_parser.add_argument("--output", help="输出路径（默认 stdout）")
    status_parser = sub.add_parser("status", help="显示 Relay 状态")
    status_parser.add_argument("--json", action="store_true")
    sub.add_parser("ensure-envoy", help="下载并校验锁定版 Envoy")
    args = parser.parse_args()
    handlers = {
        "enable": enable,
        "disable": disable,
        "rotate-token": rotate_token,
        "sync-cert": lambda _args: sync_certificate(),
        "render": lambda _args: render(),
        "validate": lambda _args: validate(),
        "profile": profile,
        "status": status,
        "ensure-envoy": lambda _args: ensure_envoy(),
    }
    try:
        handlers[args.command](args)
    except RelayError as exc:
        print("Relay 错误: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
