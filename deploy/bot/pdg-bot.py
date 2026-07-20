#!/usr/bin/env python3
"""PrivDNS Gateway — Telegram 管理 bot v3 (纯标准库, long-poll)。

出口  : 列表 / 添加(ss/vmess/trojan/vless 链接) / 删除 / 改名(级联更新引用) / 设默认出口 / 故障切换组(urltest)
分流  : 规则列表 / 添加(域名→出口|direct) / 删除 / 添加规则集(Surge .list URL→出口) / 删除规则集
诊断  : 状态 / 端到端测出口延迟(clash_api) / 流量统计(clash_api)
运维  : 重启 / 更新规则库(geosite + 规则集) / iOS 描述文件下发 / 配置备份·恢复

UI 原地编辑消息(editMessageText), 不刷屏。改 mihomo 前备份, check 失败自动回滚。
环境变量: PDG_BOT_TOKEN, PDG_BOT_ALLOWED(逗号分隔的 user id)
注: 模块可被 import (供定时任务调用 refresh_rulesets), 此时无需 token。
"""
from __future__ import annotations
import base64, contextlib, fcntl, hashlib, http.client, io, json, math, os, plistlib, pwd, re, shutil, socket, ssl, subprocess, tarfile, tempfile, threading, time, uuid
from concurrent.futures import ThreadPoolExecutor
import urllib.parse, urllib.request, urllib.error
from collections import Counter

TOKEN = os.environ.get("PDG_BOT_TOKEN", "")
ALLOWED = {int(x) for x in os.environ.get("PDG_BOT_ALLOWED", "").replace(" ", "").split(",") if x}
STATE = "/etc/mihomo/state.json"       # bot 内部状态(沿用 sing-box 风格字段, 方便复用菜单逻辑)
MIHOMO_CFG = "/etc/mihomo/config.yaml" # 实际给 mihomo 读取的原生 YAML
RS_DIR = "/etc/mihomo/rs"
MOSDNS_CONF = "/etc/mosdns/config.yaml"
MOSDNS_DIRECT = "/etc/mosdns/rules/custom_direct.txt"
MOSDNS_FORCE_PROXY = "/etc/mosdns/rules/force_proxy.txt"
RS_META = "/opt/pdg-bot/rulesets.json"
UPDATE_SCRIPT = "/opt/pdg-bot/update-rules.sh"
IOS_TMPL = "/opt/pdg-bot/pdg-dot.mobileconfig.tmpl"
CERT = os.environ.get("PDG_CERT", "/etc/mosdns/certs/fullchain.pem")
CERT_DIR = os.path.dirname(CERT)
CLASH = "http://127.0.0.1:9090"
DELAY_URL = "http://www.gstatic.com/generate_204"
API = "https://api.telegram.org/bot" + TOKEN
WLOC_STATE = "/var/lib/pdg-wloc/wloc.json"
WLOC_DOMAINS = "/etc/mosdns/rules/wloc.txt"
WLOC_CA = "/var/lib/pdg-wloc/mitmproxy/mitmproxy-ca-cert.cer"
WLOC_PRESETS = "/etc/privdns-gateway/wloc-presets.json"
WLOC_SERVICE = "pdg-wloc"
WLOC_OUTBOUND = "__pdg_wloc_mitm"
WLOC_PORT = 9080
WLOC_HOSTS = ("gs-loc.apple.com", "gs-loc-cn.apple.com")
ADBLOCK_STATE = "/var/lib/pdg-wloc/adblock.json"
ADBLOCK_RULES = "/var/lib/pdg-wloc/adblock-rules.json"
ADBLOCK_DOMAINS = "/etc/mosdns/rules/adblock.txt"
ADBLOCK_SOURCES = "/etc/privdns-gateway/adblock-sources.json"
ADBLOCK_SYNC = "/opt/pdg-bot/sync_adblock.py"
ADBLOCK_DOMAIN_PROVIDER = "__pdg_adblock_reject"
ADBLOCK_DOMAIN_PROVIDER_FILE = "/etc/mihomo/rs/__pdg_adblock_reject.mrs"
ADBLOCK_CLASSICAL_PROVIDER = "__pdg_adblock_reject_classical"
ADBLOCK_CLASSICAL_PROVIDER_FILE = "/etc/mihomo/rs/__pdg_adblock_reject_classical.yaml"
ADBLOCK_SOURCE_LIMIT = 64
ADBLOCK_FETCH_WORKERS = 4
ADBLOCK_COMPATIBILITY_LIMIT = 256
MITM_LOCK_FILE = "/run/lock/pdg-mitm.lock"
state: dict[int, str] = {}
del_sel: dict[int, set] = {}   # 删规则多选: chat -> 已勾选域名集合
_MITM_CONFIG_THREAD_LOCK = threading.RLock()
_MITM_CONFIG_LOCAL = threading.local()

# ── Telegram (复用一条 HTTPS 长连接, 省掉每次 TLS 握手 → 按钮响应更快) ──
_conn = None

def post(method, params):
    global _conn
    body = json.dumps(params).encode()
    path = "/bot" + TOKEN + "/" + method
    hdr = {"Content-Type": "application/json", "Connection": "keep-alive"}
    for attempt in (0, 1):                       # 连接断了就重连重试一次
        try:
            if _conn is None:
                _conn = http.client.HTTPSConnection("api.telegram.org", timeout=70)
            _conn.request("POST", path, body, hdr)
            data = _conn.getresponse().read()
            return json.loads(data) if data else {}
        except Exception as e:  # noqa: BLE001
            try:
                if _conn:
                    _conn.close()
            except Exception:  # noqa: BLE001
                pass
            _conn = None
            if attempt:
                print("api", method, e); return {}

def send_document(chat, filename, data, caption=""):
    """multipart/form-data 上传文件 (备份 / iOS 描述文件)。"""
    boundary = "----pdg" + uuid.uuid4().hex
    pre = []
    def fld(name, val):
        pre.append((f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{val}\r\n").encode())
    fld("chat_id", str(chat))
    if caption:
        fld("caption", caption); fld("parse_mode", "HTML")
    head = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; "
            f"filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode()
    body = b"".join(pre) + head + data + b"\r\n" + (f"--{boundary}--\r\n").encode()
    req = urllib.request.Request(API + "/sendDocument", data=body,
                                 headers={"Content-Type": "multipart/form-data; boundary=" + boundary})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.load(r)
    except Exception as e:  # noqa: BLE001
        print("senddoc", e); send_plain(chat, f"发送文件失败: {e}"); return {}

def tg_download(file_id):
    r = post("getFile", {"file_id": file_id})
    fp = r.get("result", {}).get("file_path")
    if not fp:
        raise ValueError("getFile 失败")
    with urllib.request.urlopen(f"https://api.telegram.org/file/bot{TOKEN}/{fp}", timeout=120) as resp:
        return resp.read()

# 一级菜单: 只放常用诊断 + 4 个分类入口 (展开二级, 避免一屏按钮看花眼)
MENU = {"inline_keyboard": [
    [{"text": "🔄 更新", "callback_data": "upd_check"}, {"text": "🩺 自检", "callback_data": "doctor"}],
    [{"text": "🚦 测出口", "callback_data": "test"}, {"text": "📈 流量", "callback_data": "traffic"}],
    [{"text": "📤 出口管理", "callback_data": "nav:exit"}, {"text": "📑 分流管理", "callback_data": "nav:rule"}],
    [{"text": "📱 客户端", "callback_data": "nav:client"}, {"text": "📍 iOS 定位", "callback_data": "wloc"}],
    [{"text": "🛡 去广告", "callback_data": "adblock"}, {"text": "🛠 运维", "callback_data": "nav:ops"}],
]}
BACK = {"inline_keyboard": [[{"text": "⬅️ 返回主菜单", "callback_data": "menu"}]]}
EXIT_BACK = {"inline_keyboard": [[{"text": "⬅️ 返回出口管理", "callback_data": "nav:exit"}],
                                [{"text": "🏠 主菜单", "callback_data": "menu"}]]}
RULE_BACK = {"inline_keyboard": [[{"text": "⬅️ 返回分流管理", "callback_data": "nav:rule"}],
                                [{"text": "🏠 主菜单", "callback_data": "menu"}]]}
OPS_BACK = {"inline_keyboard": [[{"text": "⬅️ 返回运维", "callback_data": "nav:ops"}],
                               [{"text": "🏠 主菜单", "callback_data": "menu"}]]}
DNS_BACK = {"inline_keyboard": [[{"text": "⬅️ 返回 DNS 上游", "callback_data": "dnsup"}],
                               [{"text": "🏠 主菜单", "callback_data": "menu"}]]}
WLOC_BACK = {"inline_keyboard": [[{"text": "⬅️ 返回 WLOC", "callback_data": "wloc"}],
                                [{"text": "📱 客户端", "callback_data": "nav:client"}],
                                [{"text": "🏠 主菜单", "callback_data": "menu"}]]}
ADBLOCK_BACK = {"inline_keyboard": [[{"text": "⬅️ 返回去广告", "callback_data": "adblock"}],
                                   [{"text": "🏠 主菜单", "callback_data": "menu"}]]}

def _back_rows(kb):
    return [row[:] for row in kb["inline_keyboard"]]

_WLOC_NUMBER = r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)"
_WLOC_COORDINATES = re.compile(
    rf"^\s*({_WLOC_NUMBER})\s*(?:[,，]|\s+)\s*({_WLOC_NUMBER})\s*$"
)

def _wloc_default():
    return {"enabled": False, "latitude": None, "longitude": None,
            "accuracy": 25, "label": None, "updated_at": None}

def _wloc_validate(latitude, longitude, accuracy=25):
    try:
        lat, lon, acc = float(latitude), float(longitude), int(accuracy)
    except (TypeError, ValueError) as e:
        raise ValueError("经纬度和精度必须是数字") from e
    if not math.isfinite(lat) or not -90 <= lat <= 90:
        raise ValueError("纬度需在 -90~90")
    if not math.isfinite(lon) or not -180 <= lon <= 180:
        raise ValueError("经度需在 -180~180")
    if not 1 <= acc <= 1000:
        raise ValueError("精度需在 1~1000 米")
    return lat, lon, acc

def _wloc_parse_coordinates(text):
    match = _WLOC_COORDINATES.fullmatch(str(text or ""))
    if not match:
        raise ValueError("格式应为：纬度,经度")
    lat, lon, _ = _wloc_validate(match.group(1), match.group(2))
    return lat, lon

def _wloc_format(value):
    return f"{float(value):.8f}".rstrip("0").rstrip(".")

def _wloc_load():
    config = _wloc_default()
    try:
        raw = json.load(open(WLOC_STATE))
        if isinstance(raw, dict):
            config.update(raw)
    except Exception:  # noqa: BLE001
        pass
    try:
        if config.get("enabled"):
            lat, lon, acc = _wloc_validate(
                config.get("latitude"), config.get("longitude"), config.get("accuracy", 25))
            config.update({"enabled": True, "latitude": lat, "longitude": lon, "accuracy": acc})
        else:
            config["enabled"] = False
    except ValueError:
        config["enabled"] = False
    return config

def _wloc_active(config=None):
    return bool((config or _wloc_load()).get("enabled"))

def _wloc_write_state(config):
    os.makedirs(os.path.dirname(WLOC_STATE), mode=0o755, exist_ok=True)
    tmp = WLOC_STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
        f.flush(); os.fsync(f.fileno())
    try:
        owner = pwd.getpwnam("pdg-wloc")
        os.chown(tmp, owner.pw_uid, owner.pw_gid)
    except (KeyError, PermissionError):  # local unit tests do not create the service account
        pass
    os.chmod(tmp, 0o600)
    os.replace(tmp, WLOC_STATE)

def _wloc_presets():
    try:
        raw = json.load(open(WLOC_PRESETS))
        items = raw.get("presets", []) if isinstance(raw, dict) else raw
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(items, list):
        return []
    presets, seen = [], set()
    for item in items:
        if not isinstance(item, dict):
            continue
        preset_id = str(item.get("id") or "").strip()
        name = " ".join(str(item.get("name") or "").split())
        if (not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", preset_id)
                or not name or len(name) > 40 or preset_id in seen):
            continue
        try:
            lat, lon, acc = _wloc_validate(
                item.get("latitude"), item.get("longitude"), item.get("accuracy", 25))
        except ValueError:
            continue
        seen.add(preset_id)
        presets.append({"id": preset_id, "name": name, "latitude": lat,
                        "longitude": lon, "accuracy": acc})
    return presets

def _wloc_preset(preset_id):
    return next((p for p in _wloc_presets() if p["id"] == preset_id), None)

def _adblock_default():
    return {"enabled": False, "updated_at": None}

def _adblock_load():
    config = _adblock_default()
    try:
        raw = json.load(open(ADBLOCK_STATE))
        if isinstance(raw, dict):
            config.update(raw)
    except Exception:  # noqa: BLE001
        pass
    config["enabled"] = bool(config.get("enabled"))
    return config

def _adblock_active(config=None):
    return bool((config or _adblock_load()).get("enabled"))

def _adblock_write_state(config):
    os.makedirs(os.path.dirname(ADBLOCK_STATE), mode=0o755, exist_ok=True)
    tmp = ADBLOCK_STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
        f.flush(); os.fsync(f.fileno())
    try:
        owner = pwd.getpwnam("pdg-wloc")
        os.chown(tmp, owner.pw_uid, owner.pw_gid)
    except (KeyError, PermissionError):
        pass
    os.chmod(tmp, 0o600)
    os.replace(tmp, ADBLOCK_STATE)

def _adblock_rules():
    try:
        payload = json.load(open(ADBLOCK_RULES))
        if not isinstance(payload, dict):
            return {}
        return payload
    except Exception:  # noqa: BLE001
        return {}

def _adblock_hosts():
    hosts = _adblock_rules().get("hosts", [])
    return sorted({str(host).strip().lower() for host in hosts
                   if re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                                   r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                                   str(host).strip().lower())})

def _adblock_source_config(strict=False):
    empty = {"sources": [], "domain_sources": [],
             "mitm_exclude_hosts": [], "compatibility_routes": []}
    try:
        with open(ADBLOCK_SOURCES, encoding="utf-8") as file:
            config = json.load(file)
    except FileNotFoundError:
        return empty
    except Exception as exc:  # noqa: BLE001
        if strict:
            raise ValueError("去广告来源配置损坏或不可读，已拒绝覆盖；请先恢复配置") from exc
        return empty
    if not isinstance(config, dict):
        if strict:
            raise ValueError("去广告来源配置不是 JSON 对象，已拒绝覆盖；请先恢复配置")
        return empty
    for key in ("sources", "domain_sources", "mitm_exclude_hosts", "compatibility_routes"):
        if key not in config:
            config[key] = []
        elif not isinstance(config[key], list):
            if strict:
                raise ValueError(f"去广告来源配置中的 {key} 不是列表，已拒绝覆盖")
            config[key] = []
    return config


def _adblock_hostname(value):
    if not isinstance(value, str):
        raise ValueError("兼容模式域名必须是字符串")
    host = value.strip().lower().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("兼容模式域名无效") from exc
    if not re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", host):
        raise ValueError("兼容模式域名无效")
    return host


def _adblock_excluded_hosts(config=None, strict=False):
    if config is None:
        config = _adblock_source_config(strict=strict)
    items = config.get("mitm_exclude_hosts", [])
    if not isinstance(items, list) or len(items) > ADBLOCK_COMPATIBILITY_LIMIT:
        if strict:
            raise ValueError(f"MITM 排除域名必须是列表且最多 {ADBLOCK_COMPATIBILITY_LIMIT} 个")
        return []
    result = []
    for value in items:
        try:
            host = _adblock_hostname(value)
        except ValueError:
            if strict:
                raise
            continue
        if host not in result:
            result.append(host)
    return result


def _adblock_compatibility_routes(config=None, mihomo_state=None, strict=False):
    if config is None:
        config = _adblock_source_config(strict=strict)
    items = config.get("compatibility_routes", [])
    if not isinstance(items, list) or len(items) > ADBLOCK_COMPATIBILITY_LIMIT:
        if strict:
            raise ValueError(f"兼容路由必须是列表且最多 {ADBLOCK_COMPATIBILITY_LIMIT} 条")
        return []
    available = ({str(item.get("tag")) for item in mihomo_state.get("outbounds", [])
                  if isinstance(item, dict) and item.get("tag")}
                 if isinstance(mihomo_state, dict) else None)
    routes = []
    seen = set()
    for item in items:
        try:
            if not isinstance(item, dict):
                raise ValueError("兼容路由条目必须是 JSON 对象")
            kind = str(item.get("type") or "").strip().lower()
            if kind not in ("domain", "domain-suffix"):
                raise ValueError("兼容路由 type 只支持 domain 或 domain-suffix")
            value = _adblock_hostname(item.get("value"))
            outbound = item.get("outbound")
            if not isinstance(outbound, str) or not outbound.strip():
                raise ValueError("兼容路由缺少出口")
            outbound = outbound.strip()
            if available is not None and outbound not in available:
                raise ValueError(f"兼容路由出口不存在: {outbound}")
        except ValueError:
            if strict:
                raise
            continue
        key = (kind, value, outbound)
        if key not in seen:
            seen.add(key)
            routes.append({"type": kind, "value": value, "outbound": outbound})
    return routes

def _adblock_write_source_config(config):
    directory = os.path.dirname(ADBLOCK_SOURCES)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    try:
        stat = os.stat(ADBLOCK_SOURCES)
    except OSError:
        stat = None
    fd, temporary = tempfile.mkstemp(prefix=".adblock-sources-", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(config, file, ensure_ascii=False, indent=2)
            file.write("\n")
            file.flush(); os.fsync(file.fileno())
        os.chmod(temporary, (stat.st_mode & 0o777) if stat else 0o600)
        if stat:
            os.chown(temporary, stat.st_uid, stat.st_gid)
        os.replace(temporary, ADBLOCK_SOURCES)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

def _adblock_source_id(url):
    return hashlib.sha256(str(url).encode()).hexdigest()[:12]

def _adblock_module_sources(config=None):
    config = config or _adblock_source_config()
    result = []
    for item in config.get("sources", []):
        if not isinstance(item, dict) or not item.get("enabled", True):
            continue
        url = str(item.get("url") or "").strip()
        if not url:
            continue
        result.append({"id": _adblock_source_id(url), "name": str(item.get("name") or url)[:80],
                       "url": url})
    return result


def _adblock_domain_sources(config=None):
    config = config or _adblock_source_config()
    result = []
    for item in config.get("domain_sources", []):
        if not isinstance(item, dict) or not item.get("enabled", True):
            continue
        url = str(item.get("url") or "").strip()
        if not url:
            continue
        result.append({
            "id": _adblock_source_id(url),
            "name": str(item.get("name") or url)[:80],
            "url": url,
            "format": str(item.get("format") or "auto"),
        })
    return result


def _adblock_plugin_url(url):
    url = str(url or "").strip()
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment or len(url) > 2000):
        raise ValueError("只接受不含账号、片段的 HTTPS 插件 URL")
    return url


def _adblock_domain_url(url):
    try:
        return _adblock_plugin_url(url)
    except ValueError as exc:
        raise ValueError("只接受不含账号、片段的 HTTPS 规则源 URL") from exc


def _adblock_plugin_name(url):
    parsed = urllib.parse.urlsplit(url)
    name = urllib.parse.unquote(os.path.basename(parsed.path)).rsplit(".", 1)[0]
    name = " ".join(name.replace("_", " ").replace("-", " ").split())
    return (name or parsed.hostname or "自定义插件")[:48]


def _adblock_domain_name(url):
    parsed = urllib.parse.urlsplit(url)
    name = urllib.parse.unquote(os.path.basename(parsed.path)).rsplit(".", 1)[0]
    name = " ".join(name.replace("_", " ").replace("-", " ").split())
    return (name or parsed.hostname or "自定义规则源")[:48]


def _adblock_check_plugin(url):
    result = sh(["python3", ADBLOCK_SYNC, "--check-module-url", url])
    if result.returncode != 0:
        return False, "插件校验失败: " + (result.stdout + result.stderr)[-300:]
    try:
        return True, json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError):
        return False, "插件校验器返回了无效结果"


def _adblock_check_domain_source(url):
    result = sh(["python3", ADBLOCK_SYNC, "--check-domain-url", url])
    if result.returncode != 0:
        return False, "规则源校验失败: " + (result.stdout + result.stderr)[-300:]
    try:
        return True, json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError):
        return False, "规则源校验器返回了无效结果"

def _mitm_active():
    return _wloc_active() or (_adblock_active() and bool(_adblock_hosts()))

@contextlib.contextmanager
def _mitm_config_lock():
    with _MITM_CONFIG_THREAD_LOCK:
        depth = getattr(_MITM_CONFIG_LOCAL, "depth", 0)
        if depth == 0:
            os.makedirs(os.path.dirname(MITM_LOCK_FILE), mode=0o755, exist_ok=True)
            descriptor = os.open(MITM_LOCK_FILE, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            except Exception:
                os.close(descriptor)
                raise
            _MITM_CONFIG_LOCAL.descriptor = descriptor
        _MITM_CONFIG_LOCAL.depth = depth + 1
        try:
            yield
        finally:
            _MITM_CONFIG_LOCAL.depth -= 1
            if _MITM_CONFIG_LOCAL.depth == 0:
                descriptor = _MITM_CONFIG_LOCAL.descriptor
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
                del _MITM_CONFIG_LOCAL.descriptor

def _nav(key):
    """二级子菜单 (标题, 键盘)。每个子菜单末尾自带「返回主菜单」。"""
    subs = {
        "exit": ("📤 <b>出口管理</b> — 选一项:", [
            [{"text": "📋 列表", "callback_data": "exit_list"}, {"text": "➕ 添加", "callback_data": "add_exit"},
             {"text": "🗑 删除", "callback_data": "del_exit"}],
            [{"text": "🎯 默认出口", "callback_data": "setfinal"}, {"text": "↕️ 出口排序", "callback_data": "order_exit"},
             {"text": "✏️ 改名", "callback_data": "ren_exit"}],
            [{"text": "🔀 新建故障组", "callback_data": "add_grp"}, {"text": "✏️ 改故障组", "callback_data": "edit_grp"}]]),
        "rule": ("📑 <b>分流管理</b> — 选一项:", [
            [{"text": "📋 规则", "callback_data": "rules"}, {"text": "➕ 加规则", "callback_data": "add_rule"},
             {"text": "🗑 删规则", "callback_data": "del_rule"}],
            [{"text": "✏️ 改出口", "callback_data": "edit_rule"}, {"text": "📚 加规则集", "callback_data": "add_rs"},
             {"text": "🗑 删规则集", "callback_data": "del_rs"}],
            [{"text": "✏️ 改规则集名", "callback_data": "edit_rs"}, {"text": "🔎 测域名(查走哪)", "callback_data": "testdom"}]]),
        "client": (f"📱 <b>客户端接入</b>\nAndroid 私密DNS 填: <code>{_dot_host()}</code>\n"
                   "iOS 可生成私密 DNS 描述文件，或使用共享 MITM 功能:", [
            [{"text": "📱 iOS 描述文件", "callback_data": "ios"},
             {"text": "📍 iOS 虚拟定位", "callback_data": "wloc"}],
            [{"text": "🛡 去广告", "callback_data": "adblock"}],
            [{"text": "🌐 DoT 自定义域名", "callback_data": "setdot"}],
            [{"text": "✈️ Telegram 出口", "callback_data": "tgexit"}]]),
        "ops": ("🛠 <b>运维</b> — 选一项:", [
            [{"text": "🔄 重启服务", "callback_data": "restart"}, {"text": "📦 更新规则库", "callback_data": "updgeo"}],
            [{"text": "💾 备份", "callback_data": "backup"}, {"text": "♻️ 恢复", "callback_data": "restore"}],
            [{"text": "🌐 DNS 上游", "callback_data": "dnsup"}, {"text": "🚀 TFO", "callback_data": "tfo"}]]),
    }
    title, rows = subs[key]
    return title, {"inline_keyboard": rows + [[{"text": "⬅️ 返回主菜单", "callback_data": "menu"}]]}

def _wloc_page():
    config = _wloc_load()
    enabled = _wloc_active(config)
    service = sh(["systemctl", "is-active", WLOC_SERVICE]).stdout.strip() == "active"
    ca_ready = os.path.exists(WLOC_CA)
    if enabled:
        label = str(config.get("label") or "").strip()
        target = ((f"<b>{_esc(label)}</b>  " if label else "")
                  + f"<code>{_wloc_format(config['latitude'])},"
                  f"{_wloc_format(config['longitude'])}</code> (±{config['accuracy']}m)")
    else:
        target = "未设置"
    text = ("📍 <b>iOS WLOC 虚拟定位</b>\n"
            "WLOC 只改写 Apple 的两个网络定位主机，普通流量仍走原有 5GPN。\n\n"
            f"状态: <b>{'已开启' if enabled else '已关闭'}</b>\n"
            f"共享 MITM: {'🟢 运行中' if service else '⚪ 未运行'}\n"
            f"共享 CA: {'✅ 已生成' if ca_ready else '未生成'}\n"
            f"目标: {target}\n\n"
            "首次使用先安装共享 CA，并在 iOS 对名为 mitmproxy 的证书开启完全信任。"
            "常用地点按钮不会发送 Telegram Location。")
    rows = [
        [{"text": "📜 安装共享 CA", "callback_data": "wloc_ca"}],
    ]
    for preset in _wloc_presets()[:12]:
        rows.append([{"text": "📌 " + preset["name"],
                      "callback_data": "wloc_use:" + preset["id"]}])
    rows.append([{"text": "✍️ 输入经纬度", "callback_data": "wloc_pick"}])
    if enabled:
        rows.append([{"text": "♻️ 关闭定位改写", "callback_data": "wloc_off"}])
    rows.extend([[{"text": "⬅️ 返回客户端", "callback_data": "nav:client"}],
                 [{"text": "🏠 主菜单", "callback_data": "menu"}]])
    return text, {"inline_keyboard": rows}

def _adblock_page():
    enabled = _adblock_active()
    service = sh(["systemctl", "is-active", WLOC_SERVICE]).stdout.strip() == "active"
    payload = _adblock_rules()
    stats = payload.get("stats", {}) if isinstance(payload, dict) else {}
    generated = str(payload.get("generated_at") or "未同步") if isinstance(payload, dict) else "未同步"
    source_config = _adblock_source_config()
    compatibility_count = len(_adblock_compatibility_routes(source_config))
    text = ("🛡 <b>服务端去广告</b>\n"
            "普通 REJECT 规则由 mihomo 直接拦截；响应改写复用共享 CA。\n\n"
            f"状态: <b>{'已开启' if enabled else '已关闭'}</b>\n"
            f"共享 MITM: {'🟢 运行中' if service else '⚪ 未运行'}\n"
            f"MITM 模块: {int(stats.get('source_count', 0) or 0)}  "
            f"主机: {int(stats.get('host_count', 0) or 0)}  "
            f"重写: {int(stats.get('rule_count', 0) or 0)}\n"
            f"兼容旁路: {compatibility_count}  "
            f"排除 MITM: {int(stats.get('excluded_host_count', 0) or 0)}\n"
            f"普通规则源: {int(stats.get('domain_source_count', 0) or 0)}  "
            f"REJECT: {int(stats.get('domain_rule_count', 0) or 0)}\n"
            f"未移植脚本: {int(stats.get('unported_scripts', 0) or 0)}  "
            f"未支持重写: {int(stats.get('unsupported_rewrites', 0) or 0)}\n"
            f"最近同步: <code>{_esc(generated)}</code>\n\n"
            "自动更新: 每日 04:30（含普通 REJECT 与 MITM 插件）\n\n"
            "MITM 只执行 reject、mock、JSON 路径修改及受限 jq；不会执行远程 JavaScript。")
    rows = [[{"text": "📜 安装共享 CA", "callback_data": "adblock_ca"}]]
    rows.append([
        {"text": "📚 REJECT 规则源", "callback_data": "adblock_domain_sources"},
        {"text": "🧩 MITM 插件", "callback_data": "adblock_sources"},
    ])
    if enabled:
        rows.append([{"text": "🔄 同步规则", "callback_data": "adblock_refresh"}])
        rows.append([{"text": "♻️ 关闭去广告", "callback_data": "adblock_off"}])
    else:
        rows.append([{"text": "✅ 同步并开启", "callback_data": "adblock_on"}])
    rows.extend([[{"text": "📱 客户端", "callback_data": "nav:client"}],
                 [{"text": "🏠 主菜单", "callback_data": "menu"}]])
    return text, {"inline_keyboard": rows}

def _adblock_sources_page():
    sources = _adblock_module_sources()
    text = ("🧩 <b>MITM 插件管理</b>\n"
            f"当前: <b>{len(sources)}</b> 个。删除以单个 Kelee/Loon 插件为单位；"
            "普通 REJECT 规则不在这里删除。")
    rows = [[{"text": "➕ 添加插件 URL", "callback_data": "adsrc_add"}]]
    for source in sources[:64]:
        label = " ".join(source["name"].split())[:42] or source["url"][:42]
        rows.append([{"text": "🗑 " + label, "callback_data": "adsrc_del:" + source["id"]}])
    rows.extend([[{"text": "⬅️ 返回去广告", "callback_data": "adblock"}],
                 [{"text": "🏠 主菜单", "callback_data": "menu"}]])
    return text, {"inline_keyboard": rows}


def _adblock_domain_sources_page():
    sources = _adblock_domain_sources()
    text = ("📚 <b>普通 REJECT 规则源</b>\n"
            f"当前: <b>{len(sources)}</b> 个。支持 Surge/Clash list、纯域名列表及 "
            "Clash payload YAML/JSON；服务器自动识别并转换为 MRS。\n"
            "URL 是唯一标识，删除后每日更新不会恢复。")
    rows = [[{"text": "➕ 添加规则源 URL", "callback_data": "adrej_add"}]]
    for source in sources[:64]:
        host = urllib.parse.urlsplit(source["url"]).hostname or ""
        label = (" ".join(source["name"].split())[:28] +
                 ((" · " + host[:18]) if host else ""))
        rows.append([{"text": "🗑 " + (label or source["url"][:42]),
                      "callback_data": "adrej_del:" + source["id"]}])
    rows.extend([[{"text": "⬅️ 返回去广告", "callback_data": "adblock"}],
                 [{"text": "🏠 主菜单", "callback_data": "menu"}]])
    return text, {"inline_keyboard": rows}

def send(chat, text, kb=None):
    p = {"chat_id": chat, "text": text, "parse_mode": "HTML",
         "reply_markup": kb or MENU, "disable_web_page_preview": True}
    if not post("sendMessage", p).get("ok"):
        p.pop("parse_mode", None)   # HTML 解析失败(文本含 < & 等, 如 mihomo 报错)→ 退回纯文本, 保证消息+键盘送达
        post("sendMessage", p)

def send_plain(chat, text):
    """纯文本回复, 不挂任何键盘 (操作结果/确认用, 避免每次刷出整排菜单)。"""
    p = {"chat_id": chat, "text": text, "parse_mode": "HTML",
         "disable_web_page_preview": True}
    if post("sendMessage", p).get("ok"):
        return
    p.pop("parse_mode", None)
    post("sendMessage", p)

def edit(chat, mid, text, kb=None):
    p = {"chat_id": chat, "message_id": mid, "text": text, "parse_mode": "HTML",
         "reply_markup": kb or MENU, "disable_web_page_preview": True}
    if post("editMessageText", p).get("ok"):
        return
    p.pop("parse_mode", None)        # 先退回纯文本重试编辑(原地保留键盘)
    if post("editMessageText", p).get("ok"):
        return
    send(chat, text, kb)             # 仍不行(如消息已删)再发新消息

def answer_cb_async(cb_id, text=None, show_alert=False):
    """后台停掉按钮转圈(独立连接, 不占用主 keep-alive、不阻塞主循环)。
    对齐 5GPN-X: 用专用线程池, 可选提示「正在处理」。"""
    def go():
        try:
            body = {"callback_query_id": cb_id}
            if text:
                body["text"] = text
                body["show_alert"] = bool(show_alert)
            urllib.request.urlopen(urllib.request.Request(
                "https://api.telegram.org/bot" + TOKEN + "/answerCallbackQuery",
                data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json"}), timeout=20).read()
        except Exception:  # noqa: BLE001
            pass
    _CB_EXECUTOR.submit(go)

# 慢操作后台跑, 主 long-poll 不堵(思路对齐 5GPN-X tgbot: background + BUSY)
_BG = ThreadPoolExecutor(max_workers=6, thread_name_prefix="pdg-bg")
_CB_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="pdg-cb")
_BUSY = set()
_BUSY_LOCK = threading.Lock()

def run_bg(fn, *args, **kwargs):
    def go():
        try:
            fn(*args, **kwargs)
        except Exception as e:  # noqa: BLE001
            print("bg err", e, flush=True)
    _BG.submit(go)

def edit_bg(chat, mid, text_fn, kb=None, busy_key=None):
    """先立刻回主循环, 后台算 text_fn() 再 edit。同一消息未完成前点第二次返回 False。"""
    key = busy_key or (chat, mid)
    with _BUSY_LOCK:
        if key in _BUSY:
            return False
        _BUSY.add(key)
    def go():
        try:
            text = text_fn() if callable(text_fn) else text_fn
            edit(chat, mid, text, kb)
        finally:
            with _BUSY_LOCK:
                _BUSY.discard(key)
    _BG.submit(go)
    return True

def send_bg(chat, text_fn, kb=None):
    def go():
        try:
            text = text_fn() if callable(text_fn) else text_fn
            if kb is None:
                send_plain(chat, text)
            else:
                send(chat, text, kb)
        except Exception as e:  # noqa: BLE001
            print("send_bg err", e, flush=True)
    _BG.submit(go)

def delete_message(chat, mid):
    """尽量删掉含节点密码的消息(对齐 5GPN-X process_add_exit_message)。"""
    if mid is None:
        return False
    try:
        r = post("deleteMessage", {"chat_id": chat, "message_id": mid})
        return bool(isinstance(r, dict) and r.get("ok"))
    except Exception:  # noqa: BLE001
        return False

def is_busy(chat, mid):
    with _BUSY_LOCK:
        return (chat, mid) in _BUSY

def sh(cmd, timeout=180):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

# ── clash_api (mihomo external-controller) ──
def clash_get(path):
    with urllib.request.urlopen(CLASH + path, timeout=12) as r:
        return json.load(r)

def clash_up():
    try:
        clash_get("/version"); return True
    except Exception:  # noqa: BLE001
        return False

# ── mihomo 配置生成 ──
def load():
    return json.load(open(STATE))

def _yaml_scalar(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if v is None:
        return "null"
    return json.dumps(str(v), ensure_ascii=False)

def _yaml_dump(v, indent=0):
    sp = " " * indent
    if isinstance(v, dict):
        lines = []
        for k, val in v.items():
            key = str(k)
            if isinstance(val, (dict, list)):
                lines.append(f"{sp}{key}:")
                lines.append(_yaml_dump(val, indent + 2))
            else:
                lines.append(f"{sp}{key}: {_yaml_scalar(val)}")
        return "\n".join(lines)
    if isinstance(v, list):
        if not v:
            return sp + "[]"
        lines = []
        for item in v:
            if isinstance(item, dict):
                lines.append(f"{sp}-")
                lines.append(_yaml_dump(item, indent + 2))
            elif isinstance(item, list):
                lines.append(f"{sp}-")
                lines.append(_yaml_dump(item, indent + 2))
            else:
                lines.append(f"{sp}- {_yaml_scalar(item)}")
        return "\n".join(lines)
    return sp + _yaml_scalar(v)

def _duration_seconds(v, default=180):
    if isinstance(v, int):
        return v
    s = str(v or "").strip().lower()
    m = re.match(r"^(\d+)(ms|s|m|h)?$", s)
    if not m:
        return default
    n = int(m.group(1)); u = m.group(2) or "s"
    return max(1, n // 1000) if u == "ms" else n * (60 if u == "m" else 3600 if u == "h" else 1)

def _mihomo_tls(proxy, tls):
    if not tls or not tls.get("enabled"):
        return
    proxy["tls"] = True
    if tls.get("server_name"):
        proxy["servername"] = tls["server_name"]
    if tls.get("insecure"):
        proxy["skip-cert-verify"] = True
    if tls.get("utls", {}).get("fingerprint"):
        proxy["client-fingerprint"] = tls["utls"]["fingerprint"]
    reality = tls.get("reality") or {}
    if reality.get("enabled"):
        ro = {}
        if reality.get("public_key"):
            ro["public-key"] = reality["public_key"]
        if reality.get("short_id"):
            ro["short-id"] = reality["short_id"]
        proxy["reality-opts"] = ro

def _mihomo_transport(proxy, transport):
    if not transport:
        return
    typ = transport.get("type")
    if typ == "ws":
        proxy["network"] = "ws"
        opts = {}
        if transport.get("path"):
            opts["path"] = transport["path"]
        if transport.get("headers"):
            opts["headers"] = transport["headers"]
        if opts:
            proxy["ws-opts"] = opts
    elif typ == "grpc":
        proxy["network"] = "grpc"
        if transport.get("service_name"):
            proxy["grpc-opts"] = {"grpc-service-name": transport["service_name"]}

def _mihomo_proxy(o):
    typ = o.get("type")
    name = o.get("tag") or o.get("name")
    if typ == "direct":
        return {"name": name, "type": "direct"}
    base = {"name": name, "server": o.get("server"), "port": int(o.get("server_port", 0) or 0)}
    if typ == "shadowsocks":
        p = {**base, "type": "ss", "cipher": o.get("method"), "password": o.get("password", ""), "udp": True}
    elif typ == "vmess":
        p = {**base, "type": "vmess", "uuid": o.get("uuid"), "alterId": int(o.get("alter_id", 0) or 0),
             "cipher": o.get("security") or "auto"}
        _mihomo_tls(p, o.get("tls")); _mihomo_transport(p, o.get("transport"))
    elif typ == "trojan":
        p = {**base, "type": "trojan", "password": o.get("password", "")}
        _mihomo_tls(p, o.get("tls")); _mihomo_transport(p, o.get("transport"))
    elif typ == "vless":
        p = {**base, "type": "vless", "uuid": o.get("uuid")}
        if o.get("flow"):
            p["flow"] = o["flow"]
        _mihomo_tls(p, o.get("tls")); _mihomo_transport(p, o.get("transport"))
    elif typ == "hysteria2":
        p = {**base, "type": "hysteria2", "password": o.get("password", "")}
        _mihomo_tls(p, o.get("tls"))
        if o.get("obfs"):
            p["obfs"] = o["obfs"].get("type")
            p["obfs-password"] = o["obfs"].get("password", "")
    elif typ == "tuic":
        p = {**base, "type": "tuic", "uuid": o.get("uuid"), "password": o.get("password", "")}
        _mihomo_tls(p, o.get("tls"))
        if o.get("congestion_control"):
            p["congestion-controller"] = o["congestion_control"]
        if o.get("udp_relay_mode"):
            p["udp-relay-mode"] = o["udp_relay_mode"]
    elif typ == "anytls":
        p = {**base, "type": "anytls", "password": o.get("password", "")}
        _mihomo_tls(p, o.get("tls"))
    elif typ == "socks":
        p = {**base, "type": "socks5", "udp": True}
        if o.get("username"):
            p["username"] = o["username"]
        if o.get("password"):
            p["password"] = o["password"]
    elif typ == "http":
        p = {**base, "type": "http"}
        if o.get("username"):
            p["username"] = o["username"]
        if o.get("password"):
            p["password"] = o["password"]
        _mihomo_tls(p, o.get("tls"))
    else:
        raise ValueError("不支持的出口类型: " + str(typ))
    if o.get("tcp_fast_open"):
        p["tfo"] = True
    return p

def _rule_provider_path(name, meta):
    info = meta.get(name, {})
    p = info.get("path") or ""
    if p.startswith(RS_DIR + "/"):
        return p
    yaml_path = os.path.join(RS_DIR, name + ".yaml")
    legacy_json = os.path.join(RS_DIR, name + ".json")
    if not os.path.exists(yaml_path) and os.path.exists(legacy_json):
        try:
            rules = json.load(open(legacy_json)).get("rules", [])
            with open(yaml_path, "w") as f:
                f.write("payload:\n")
                for rule in rules:
                    for x in rule.get("domain", []):
                        f.write("  - DOMAIN," + x + "\n")
                    for x in rule.get("domain_suffix", []):
                        f.write("  - DOMAIN-SUFFIX," + x + "\n")
                    for x in rule.get("domain_keyword", []):
                        f.write("  - DOMAIN-KEYWORD," + x + "\n")
                    for x in rule.get("ip_cidr", []):
                        f.write("  - IP-CIDR," + x + "\n")
        except Exception:  # noqa: BLE001
            pass
    return os.path.join(RS_DIR, name + ".yaml")

def _mihomo_config(c):
    meta = _rs_meta()
    proxies, groups = [], []
    for o in c.get("outbounds", []):
        if o.get("type") == "urltest":
            groups.append({"name": o["tag"], "type": "url-test", "proxies": o.get("outbounds", []),
                           "url": o.get("url", DELAY_URL), "interval": _duration_seconds(o.get("interval"), 180),
                           "tolerance": int(o.get("tolerance", 50) or 50)})
        else:
            proxies.append(_mihomo_proxy(o))
    wloc_enabled = _wloc_active()
    adblock_enabled = _adblock_active()
    adblock_hosts = _adblock_hosts() if adblock_enabled else []
    compatibility_routes = []
    if adblock_enabled:
        compatibility_routes = _adblock_compatibility_routes(
            _adblock_source_config(strict=True), c, strict=True)
    if wloc_enabled or adblock_hosts:
        proxies.append({"name": WLOC_OUTBOUND, "type": "http",
                        "server": "127.0.0.1", "port": WLOC_PORT})
    providers = {}
    for rs in c.get("route", {}).get("rule_set", []):
        name = rs.get("tag")
        if not name:
            continue
        providers[name] = {"type": "file", "behavior": "classical", "path": _rule_provider_path(name, meta)}
    adblock_stats = _adblock_rules().get("stats", {}) if _adblock_active() else {}
    domain_rule_count = int(adblock_stats.get("domain_rule_count", 0) or 0)
    domain_mrs_rule_count = int(adblock_stats.get("domain_mrs_rule_count", 0) or 0)
    domain_classical_rule_count = int(adblock_stats.get("domain_classical_rule_count", 0) or 0)
    if domain_rule_count and domain_mrs_rule_count:
        providers[ADBLOCK_DOMAIN_PROVIDER] = {
            "type": "file", "behavior": "domain", "format": "mrs",
            "path": ADBLOCK_DOMAIN_PROVIDER_FILE,
        }
    if domain_rule_count and domain_classical_rule_count:
        providers[ADBLOCK_CLASSICAL_PROVIDER] = {
            "type": "file", "behavior": "classical", "path": ADBLOCK_CLASSICAL_PROVIDER_FILE,
        }
    # Exact-domain rules must precede the server-IP reject rule. The phone sees the
    # gateway IP from mosdns; mihomo's TLS sniffer restores the Apple hostname.
    mitm_hosts = (list(WLOC_HOSTS) if wloc_enabled else []) + adblock_hosts
    rules = [f"{route['type'].upper()},{route['value']},{route['outbound']}"
             for route in compatibility_routes]

    # Force-gateway rule sets (for long-lived system services such as APNs) must
    # precede REJECT and MITM rules, while remaining TLS pass-through.
    for r in c.get("route", {}).get("rules", []):
        if not r.get("force_gateway") or not r.get("outbound"):
            continue
        target = r["outbound"]
        if r.get("rule_set"):
            rules.append(f"RULE-SET,{r['rule_set']},{target}")
        for d in r.get("domain", []):
            rules.append(f"DOMAIN,{d},{target}")
        for d in r.get("domain_suffix", []):
            rules.append(f"DOMAIN-SUFFIX,{d},{target}")
        for k in r.get("domain_keyword", []):
            rules.append(f"DOMAIN-KEYWORD,{k},{target}")
        for cidr in r.get("ip_cidr", []):
            rules.append(f"IP-CIDR,{cidr},{target},no-resolve")
    # A supported path rewrite is more specific than a broad domain denylist.
    # Keep exact MITM hosts first so a synthetic no-ad response can clear SDK
    # state instead of a connection-level reject leaving cached creatives alive.
    rules.extend(f"DOMAIN,{host},{WLOC_OUTBOUND}" for host in dict.fromkeys(mitm_hosts))
    if domain_rule_count and domain_mrs_rule_count:
        rules.append(f"RULE-SET,{ADBLOCK_DOMAIN_PROVIDER},REJECT")
    if domain_rule_count and domain_classical_rule_count:
        rules.append(f"RULE-SET,{ADBLOCK_CLASSICAL_PROVIDER},REJECT")
    for r in c.get("route", {}).get("rules", []):
        if r.get("force_gateway"):
            continue
        target = r.get("outbound")
        if r.get("action") == "reject":
            for cidr in r.get("ip_cidr", []):
                rules.append(f"IP-CIDR,{cidr},REJECT-DROP,no-resolve")
            continue
        if not target:
            continue
        if r.get("inbound") == [TG_INBOUND]:
            rules.append(f"IN-NAME,{TG_INBOUND},{target}")
            continue
        if r.get("rule_set"):
            rules.append(f"RULE-SET,{r['rule_set']},{target}")
            continue
        for d in r.get("domain", []):
            rules.append(f"DOMAIN,{d},{target}")
        for d in r.get("domain_suffix", []):
            rules.append(f"DOMAIN-SUFFIX,{d},{target}")
        for k in r.get("domain_keyword", []):
            rules.append(f"DOMAIN-KEYWORD,{k},{target}")
        for cidr in r.get("ip_cidr", []):
            rules.append(f"IP-CIDR,{cidr},{target},no-resolve")
    rules.append("MATCH," + c.get("route", {}).get("final", "jp"))
    cfg = {
        "tproxy-port": 7893,
        "allow-lan": True,
        "bind-address": "*",
        "mode": "rule",
        "log-level": "warning",
        "external-controller": "127.0.0.1:9090",
        "ipv6": False,
        "listeners": [{"name": TG_INBOUND, "type": "mixed", "port": 8445, "listen": "0.0.0.0"}],
        "sniffer": {
            "enable": True, "force-dns-mapping": True, "parse-pure-ip": True, "override-destination": True,
            "sniff": {"HTTP": {"ports": ["1-65535"]}, "TLS": {"ports": ["1-65535"]}, "QUIC": {"ports": ["1-65535"]}},
        },
        "dns": {"enable": True, "ipv6": False, "nameserver": ["22.22.22.22"]},
        "proxies": proxies,
        "rules": rules,
    }
    if groups:
        cfg["proxy-groups"] = groups
    if providers:
        cfg["rule-providers"] = providers
    return cfg

def _write(c):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    os.makedirs(RS_DIR, exist_ok=True)
    t = STATE + ".tmp"
    with open(t, "w") as f:
        json.dump(c, f, ensure_ascii=False, indent=2)
    os.chmod(t, 0o600)
    os.replace(t, STATE)
    y = MIHOMO_CFG + ".tmp"
    with open(y, "w") as f:
        f.write("# Generated by pdg-bot. Edit /etc/mihomo/state.json via bot/pdg, not this file.\n")
        f.write(_yaml_dump(_mihomo_config(c)) + "\n")
    os.chmod(y, 0o600)
    os.replace(y, MIHOMO_CFG)

def _svc_active(unit, need=3, delay=0.6, max_polls=15):
    """确认服务"稳定" active: 要求连续 need 次观测都是 active。
    systemd 默认 Type=simple, restart 返 0 只代表 exec 成功; 起来又崩(flapping)时单看一次会误判 ——
    崩溃/重启间隙的 failed/activating 会打断连击, 故要求连续保持才算稳。"""
    streak = 0
    for _ in range(max_polls):
        if sh(["systemctl", "is-active", unit]).stdout.strip() == "active":
            streak += 1
            if streak >= need:
                return True
        else:
            streak = 0
        time.sleep(delay)
    return False

def apply_sb(modify):
    shutil.copy(STATE, STATE + ".botbak"); os.chmod(STATE + ".botbak", 0o600)
    if os.path.exists(MIHOMO_CFG):
        shutil.copy(MIHOMO_CFG, MIHOMO_CFG + ".botbak"); os.chmod(MIHOMO_CFG + ".botbak", 0o600)
    c = load(); modify(c); _write(c)
    chk = sh(["mihomo", "-t", "-d", os.path.dirname(MIHOMO_CFG)])
    if chk.returncode != 0:
        shutil.copy(STATE + ".botbak", STATE)
        if os.path.exists(MIHOMO_CFG + ".botbak"):
            shutil.copy(MIHOMO_CFG + ".botbak", MIHOMO_CFG)
        return False, "配置校验失败,已回滚:\n" + (chk.stdout + chk.stderr)[-400:]
    sh(["systemctl", "reset-failed", "mihomo"])   # 清掉 start-limit 计数: 连改多条快速多次重启不会触发限速锁死
    r = sh(["systemctl", "restart", "mihomo"])
    if r.returncode != 0 or not _svc_active("mihomo"):   # 没起来/起来又崩, 还原文件再重启一次, 别把代理留在挂掉状态
        shutil.copy(STATE + ".botbak", STATE)
        if os.path.exists(MIHOMO_CFG + ".botbak"):
            shutil.copy(MIHOMO_CFG + ".botbak", MIHOMO_CFG)
        sh(["systemctl", "reset-failed", "mihomo"]); sh(["systemctl", "restart", "mihomo"])
        return False, "重启 mihomo 失败, 已还原上一份配置:\n" + (r.stdout + r.stderr)[-300:]
    return True, ""

def _wloc_mosdns_ready():
    try:
        text = open(MOSDNS_CONF).read()
    except OSError:
        return False
    return all(marker in text for marker in
               ("tag: geosite_wloc", "tag: wloc_sequence", "qname $geosite_wloc"))

def _adblock_mosdns_ready():
    try:
        text = open(MOSDNS_CONF).read()
    except OSError:
        return False
    return all(marker in text for marker in
               ("tag: geosite_adblock", "tag: wloc_sequence", "qname $geosite_adblock"))

def _force_proxy_mosdns_ready():
    try:
        text = open(MOSDNS_CONF).read()
    except OSError:
        return False
    return all(marker in text for marker in
               ("tag: geosite_force_proxy", "tag: wloc_sequence",
                "qname $geosite_force_proxy"))

def _wloc_write_domains(enabled):
    os.makedirs(os.path.dirname(WLOC_DOMAINS), exist_ok=True)
    tmp = WLOC_DOMAINS + ".tmp"
    with open(tmp, "w") as f:
        if enabled:
            f.write("\n".join("full:" + host for host in WLOC_HOSTS) + "\n")
        f.flush(); os.fsync(f.fileno())
    os.chmod(tmp, 0o644)
    os.replace(tmp, WLOC_DOMAINS)

def _adblock_write_domains(enabled):
    os.makedirs(os.path.dirname(ADBLOCK_DOMAINS), exist_ok=True)
    tmp = ADBLOCK_DOMAINS + ".tmp"
    with open(tmp, "w") as f:
        if enabled:
            hosts = _adblock_hosts()
            if hosts:
                f.write("\n".join("full:" + host for host in hosts) + "\n")
        f.flush(); os.fsync(f.fileno())
    os.chmod(tmp, 0o644)
    os.replace(tmp, ADBLOCK_DOMAINS)

def _mitm_set_service(enabled):
    if enabled:
        result = sh(["systemctl", "enable", "--now", WLOC_SERVICE])
        if result.returncode != 0 or not _svc_active(WLOC_SERVICE, need=2, max_polls=12):
            return False, "共享 MITM 服务启动失败: " + (result.stdout + result.stderr)[-300:]
        return True, ""
    result = sh(["systemctl", "disable", "--now", WLOC_SERVICE])
    if result.returncode != 0:
        return False, "共享 MITM 服务停止失败: " + (result.stdout + result.stderr)[-300:]
    return True, ""

def _wloc_restart_mosdns():
    result = sh(["systemctl", "restart", "mosdns"])
    if result.returncode != 0 or not _svc_active("mosdns"):
        return False, "mosdns 重启失败: " + (result.stdout + result.stderr)[-300:]
    return True, ""

def _wloc_restore_runtime(config):
    """Best-effort rollback for a failed WLOC enable/disable transaction."""
    enabled = _wloc_active(config)
    _wloc_write_state(config)
    _wloc_write_domains(enabled)
    apply_sb(lambda c: None)
    _wloc_restart_mosdns()
    _mitm_set_service(_mitm_active())

def _adblock_restore_runtime(config):
    enabled = _adblock_active(config)
    _adblock_write_state(config)
    try:
        _adblock_write_domains(enabled)
    except ValueError:
        _adblock_write_domains(False)
    apply_sb(lambda c: None)
    _wloc_restart_mosdns()
    _mitm_set_service(_mitm_active())


def _adblock_sync_timeout():
    config = _adblock_source_config(strict=True)
    _adblock_excluded_hosts(config, strict=True)
    _adblock_compatibility_routes(config, load(), strict=True)
    counts = []
    for key in ("sources", "domain_sources"):
        count = sum(1 for item in config[key]
                    if isinstance(item, dict) and item.get("enabled", True))
        if count > ADBLOCK_SOURCE_LIMIT:
            raise ValueError(f"去广告来源配置中的 {key} 超过 {ADBLOCK_SOURCE_LIMIT} 个")
        counts.append(count)
    module_batches = math.ceil(counts[0] / ADBLOCK_FETCH_WORKERS)
    domain_batches = math.ceil(counts[1] / ADBLOCK_FETCH_WORKERS)
    # Four downloads run concurrently per compiler batch. Leave enough time for
    # every curl deadline, the 120-second MRS conversion, and process overhead.
    return max(180, 240 + module_batches * 30 + domain_batches * 50)


def _adblock_sync_rules():
    try:
        timeout = _adblock_sync_timeout()
        result = sh(["python3", ADBLOCK_SYNC, "--sources", ADBLOCK_SOURCES,
                     "--output", ADBLOCK_RULES,
                     "--domain-output", ADBLOCK_DOMAIN_PROVIDER_FILE,
                     "--classical-output", ADBLOCK_CLASSICAL_PROVIDER_FILE],
                    timeout=timeout)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        return False, f"规则同步失败: {exc}"
    if result.returncode != 0:
        return False, "规则同步失败: " + (result.stdout + result.stderr)[-400:]
    payload = _adblock_rules()
    stats = payload.get("stats", {}) if isinstance(payload, dict) else {}
    hosts = _adblock_hosts()
    rewrite_count = int(stats.get("rule_count", 0) or 0)
    declared_host_count = int(stats.get("declared_host_count", len(hosts)) or 0)
    excluded_host_count = int(stats.get("excluded_host_count", 0) or 0)
    all_hosts_excluded = (rewrite_count and not hosts and declared_host_count > 0
                          and excluded_host_count == declared_host_count)
    if bool(hosts) != bool(rewrite_count) and not all_hosts_excluded:
        return False, "MITM 精确主机和声明式规则不一致"
    domain_rule_count = int(stats.get("domain_rule_count", 0) or 0)
    domain_mrs_rule_count = int(stats.get("domain_mrs_rule_count", 0) or 0)
    domain_classical_rule_count = int(stats.get("domain_classical_rule_count", 0) or 0)
    if domain_rule_count != domain_mrs_rule_count + domain_classical_rule_count:
        return False, "普通 REJECT 规则统计不一致"
    if domain_mrs_rule_count and not os.path.exists(ADBLOCK_DOMAIN_PROVIDER_FILE):
        return False, "普通 REJECT MRS 规则缺失"
    if domain_classical_rule_count and not os.path.exists(ADBLOCK_CLASSICAL_PROVIDER_FILE):
        return False, "普通 REJECT 兼容规则缺失"
    return True, stats

def _wloc_ensure_ca():
    if os.path.exists(WLOC_CA) and os.path.getsize(WLOC_CA) > 0:
        return True, ""
    keep_running = _mitm_active()
    result = sh(["systemctl", "start", WLOC_SERVICE])
    if result.returncode != 0:
        return False, "无法启动共享 MITM 生成 CA: " + (result.stdout + result.stderr)[-300:]
    for _ in range(30):
        if os.path.exists(WLOC_CA) and os.path.getsize(WLOC_CA) > 0:
            if not keep_running:
                sh(["systemctl", "stop", WLOC_SERVICE])
            return True, ""
        time.sleep(0.2)
    if not keep_running:
        sh(["systemctl", "stop", WLOC_SERVICE])
    return False, "共享 MITM 已启动，但 6 秒内没有生成 CA"

def set_wloc(latitude, longitude, accuracy=25, label=None):
    lat, lon, acc = _wloc_validate(latitude, longitude, accuracy)
    label = " ".join(str(label or "").split())[:64] or None
    display_label = _esc(label) + " " if label else ""
    with _mitm_config_lock():
        if not _wloc_mosdns_ready():
            return False, "mosdns 尚未安装 WLOC 分支，请先运行 sudo pdg update"
        previous = _wloc_load()
        ok, msg = _mitm_set_service(True)
        if not ok:
            return False, msg
        current = {"enabled": True, "latitude": lat, "longitude": lon, "accuracy": acc,
                   "label": label,
                   "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
        _wloc_write_state(current)

        # Coordinate changes while already enabled are intentionally restart-free.
        if _wloc_active(previous):
            return True, (f"✅ WLOC 目标已更新为 "
                          f"{display_label}{_wloc_format(lat)}, {_wloc_format(lon)} "
                          f"(±{acc}m)，mosdns/mihomo 未重启")

        ok, msg = apply_sb(lambda c: None)  # add local HTTP outbound + exact-domain rules first
        if not ok:
            _wloc_restore_runtime(previous)
            return False, msg
        _wloc_write_domains(True)
        ok, msg = _wloc_restart_mosdns()    # expose the gateway A record only after route is ready
        if not ok:
            _wloc_restore_runtime(previous)
            return False, msg
        return True, (f"✅ WLOC 已开启: "
                      f"{display_label}{_wloc_format(lat)}, {_wloc_format(lon)} (±{acc}m)\n"
                      "仅 gs-loc.apple.com / gs-loc-cn.apple.com 进入 MITM")

def disable_wloc():
    with _mitm_config_lock():
        previous = _wloc_load()
        disabled = _wloc_default()
        _wloc_write_state(disabled)         # any in-flight MITM response becomes passthrough first
        _wloc_write_domains(False)
        ok, msg = _wloc_restart_mosdns()    # clear lazy DNS cache before removing the route
        if not ok:
            _wloc_restore_runtime(previous)
            return False, msg
        ok, msg = apply_sb(lambda c: None)
        if not ok:
            _wloc_restore_runtime(previous)
            return False, msg
        ok, msg = _mitm_set_service(_mitm_active())
        if not ok:
            return False, msg
        return True, "✅ 定位改写已关闭，Apple 定位恢复原始直连；CA 和其它 MITM 功能已保留"

def enable_adblock():
    with _mitm_config_lock():
        if not _adblock_mosdns_ready():
            return False, "mosdns 尚未安装去广告分支，请先运行 sudo pdg update"
        previous = _adblock_load()
        backup = ADBLOCK_RULES + ".botbak"
        provider_files = (ADBLOCK_DOMAIN_PROVIDER_FILE, ADBLOCK_CLASSICAL_PROVIDER_FILE)
        provider_backups = {path: path + ".botbak" for path in provider_files}
        had_rules = os.path.exists(ADBLOCK_RULES)
        had_providers = {path: os.path.exists(path) for path in provider_files}
        if had_rules:
            shutil.copy2(ADBLOCK_RULES, backup)
            os.chmod(backup, 0o600)
        elif os.path.exists(backup):
            os.unlink(backup)
        for path, backup_path in provider_backups.items():
            if had_providers[path]:
                shutil.copy2(path, backup_path)
                os.chmod(backup_path, 0o600)
            elif os.path.exists(backup_path):
                os.unlink(backup_path)

        def restore_files():
            if had_rules and os.path.exists(backup):
                os.replace(backup, ADBLOCK_RULES)
            elif not had_rules and os.path.exists(ADBLOCK_RULES):
                os.unlink(ADBLOCK_RULES)
            for path, backup_path in provider_backups.items():
                if had_providers[path] and os.path.exists(backup_path):
                    os.replace(backup_path, path)
                elif not had_providers[path] and os.path.exists(path):
                    os.unlink(path)

        def restore():
            restore_files()
            _adblock_restore_runtime(previous)

        ok, detail = _adblock_sync_rules()
        if not ok:
            restore_files()
            return False, detail
        ok, msg = _mitm_set_service(_wloc_active() or bool(_adblock_hosts()))
        if not ok:
            restore()
            return False, msg
        current = {"enabled": True, "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
        _adblock_write_state(current)
        ok, msg = apply_sb(lambda c: None)
        if not ok:
            restore()
            return False, msg
        try:
            _adblock_write_domains(True)
        except ValueError as exc:
            restore()
            return False, str(exc)
        ok, msg = _wloc_restart_mosdns()
        if not ok:
            restore()
            return False, msg
        for path in (backup, *provider_backups.values()):
            if os.path.exists(path):
                os.unlink(path)
        return True, ("✅ 服务端去广告已开启: "
                      f"{detail.get('source_count', 0)} 模块 / "
                      f"{detail.get('host_count', 0)} 主机 / "
                      f"{detail.get('rule_count', 0)} 规则\n"
                      f"兼容排除: {detail.get('excluded_host_count', 0)} 主机\n"
                      f"普通 REJECT: {detail.get('domain_source_count', 0)} 源 / "
                      f"{detail.get('domain_rule_count', 0)} 规则\n"
                      f"未执行远程脚本: {detail.get('unported_scripts', 0)}")

def disable_adblock():
    with _mitm_config_lock():
        previous = _adblock_load()
        _adblock_write_state(_adblock_default())
        _adblock_write_domains(False)
        ok, msg = _wloc_restart_mosdns()
        if not ok:
            _adblock_restore_runtime(previous)
            return False, msg
        ok, msg = apply_sb(lambda c: None)
        if not ok:
            _adblock_restore_runtime(previous)
            return False, msg
        ok, msg = _mitm_set_service(_mitm_active())
        if not ok:
            return False, msg
        return True, "✅ 去广告已关闭；WLOC 和 CA 不受影响"

def refresh_adblock():
    with _mitm_config_lock():
        if _adblock_active():
            return enable_adblock()
        ok, detail = _adblock_sync_rules()
        if not ok:
            return False, detail
        return True, (f"去广告未开启，已更新缓存（普通 REJECT {detail.get('domain_rule_count', 0)} 条）")

def add_adblock_plugin(url):
    try:
        url = _adblock_plugin_url(url)
    except ValueError as exc:
        return False, str(exc)
    ok, detail = _adblock_check_plugin(url)
    if not ok:
        return False, detail
    with _mitm_config_lock():
        try:
            config = _adblock_source_config(strict=True)
        except ValueError as exc:
            return False, str(exc)
        sources = _adblock_module_sources(config)
        if any(item["url"] == url for item in sources):
            return False, "这个插件 URL 已存在"
        if len(sources) >= ADBLOCK_SOURCE_LIMIT:
            return False, f"MITM 插件最多 {ADBLOCK_SOURCE_LIMIT} 个"
        previous = json.loads(json.dumps(config))
        config["sources"].append({
            "name": _adblock_plugin_name(url), "url": url, "enabled": True,
        })
        _adblock_write_source_config(config)
        if _adblock_active():
            refreshed, message = enable_adblock()
            if not refreshed:
                _adblock_write_source_config(previous)
                return False, message
        return True, (f"✅ 已添加插件 {_adblock_plugin_name(url)}；"
                      f"声明式重写 {detail.get('supported_rewrites', 0)} 条，"
                      f"未执行脚本 {detail.get('unported_scripts', 0)} 条")

def delete_adblock_plugin(source_id):
    with _mitm_config_lock():
        try:
            config = _adblock_source_config(strict=True)
        except ValueError as exc:
            return False, str(exc)
        previous = json.loads(json.dumps(config))
        removed = None
        kept = []
        for item in config.get("sources", []):
            url = str(item.get("url") or "") if isinstance(item, dict) else ""
            if removed is None and _adblock_source_id(url) == source_id:
                removed = item
            else:
                kept.append(item)
        if removed is None:
            return False, "插件不存在或已删除"
        config["sources"] = kept
        _adblock_write_source_config(config)
        if _adblock_active():
            refreshed, message = enable_adblock()
            if not refreshed:
                _adblock_write_source_config(previous)
                return False, message
        return True, "✅ 已删除插件 " + str(removed.get("name") or removed.get("url") or "")


def add_adblock_domain_source(url):
    try:
        url = _adblock_domain_url(url)
    except ValueError as exc:
        return False, str(exc)
    ok, detail = _adblock_check_domain_source(url)
    if not ok:
        return False, detail
    with _mitm_config_lock():
        try:
            config = _adblock_source_config(strict=True)
        except ValueError as exc:
            return False, str(exc)
        if any(str(item.get("url") or "").strip() == url
               for item in config.get("domain_sources", []) if isinstance(item, dict)):
            return False, "这个规则源 URL 已存在"
        if len(_adblock_domain_sources(config)) >= ADBLOCK_SOURCE_LIMIT:
            return False, f"普通 REJECT 规则源最多 {ADBLOCK_SOURCE_LIMIT} 个"
        previous = json.loads(json.dumps(config))
        config["domain_sources"].append({
            "name": _adblock_domain_name(url), "url": url,
            "format": "auto", "enabled": True,
        })
        _adblock_write_source_config(config)
        active = _adblock_active()
        if active:
            refreshed, message = enable_adblock()
            if not refreshed:
                _adblock_write_source_config(previous)
                return False, message
        status = "已重新编译并应用" if active else "将在下次启用或定时更新时编译"
        return True, (f"✅ 已添加规则源 {_adblock_domain_name(url)}；"
                      f"识别 {detail.get('supported_rules', 0)} 条，"
                      f"MRS {detail.get('domain_mrs_rule_count', 0)} 条，"
                      f"兼容规则 {detail.get('domain_classical_rule_count', 0)} 条；{status}")


def delete_adblock_domain_source(source_id):
    with _mitm_config_lock():
        try:
            config = _adblock_source_config(strict=True)
        except ValueError as exc:
            return False, str(exc)
        previous = json.loads(json.dumps(config))
        removed = None
        kept = []
        for item in config.get("domain_sources", []):
            url = str(item.get("url") or "") if isinstance(item, dict) else ""
            if removed is None and _adblock_source_id(url) == source_id:
                removed = item
            else:
                kept.append(item)
        if removed is None:
            return False, "规则源不存在或已删除"
        config["domain_sources"] = kept
        _adblock_write_source_config(config)
        if _adblock_active():
            refreshed, message = enable_adblock()
            if not refreshed:
                _adblock_write_source_config(previous)
                return False, message
        return True, "✅ 已按 URL 删除规则源 " + str(removed.get("url") or "")

# 可作出口的代理协议(决定哪些出站算"出口": 可选默认/故障组成员/测出口/删除)。
PROXY_TYPES = ("shadowsocks", "vmess", "trojan", "vless", "hysteria", "hysteria2",
               "tuic", "anytls", "shadowtls", "socks", "http")

def proxy_outbounds(c):
    return [o for o in c["outbounds"] if o.get("type") in PROXY_TYPES]

def exit_tags(c):
    """可作分流目标/默认出口的全部出口 (含 direct 与 urltest 故障组)。"""
    return [o["tag"] for o in c["outbounds"] if o.get("type") in PROXY_TYPES + ("direct", "urltest")]

def concrete_tags(c):
    """具体出口 (可作故障组成员; 排除 urltest 组自身, 防嵌套环)。"""
    return [o["tag"] for o in c["outbounds"] if o.get("type") in PROXY_TYPES + ("direct",)]

def deletable_tags(c):
    """可删除的出口/组 (代理出口 + urltest 组; 不含 jp direct)。"""
    return [o["tag"] for o in c["outbounds"] if o.get("type") in PROXY_TYPES + ("urltest",)]

def _tag(name, host, port):
    return re.sub(r"[^A-Za-z0-9_.-]", "-", (name or f"{host}:{port}"))[:40] or "exit"

# ── 链接解析 (ss/vmess/trojan/vless) ──
def parse_link(link):
    link = link.strip()
    if link.startswith("ss://"):
        return _parse_ss(link)
    if link.startswith("vmess://"):
        return _parse_vmess(link)
    if link.startswith("trojan://"):
        return _parse_trojan(link)
    if link.startswith("vless://"):
        return _parse_vless(link)                     # 含 reality/flow
    if link.startswith(("hysteria2://", "hy2://")):
        return _parse_hysteria2(link)
    if link.startswith("tuic://"):
        return _parse_tuic(link)
    if link.startswith("anytls://"):
        return _parse_anytls(link)
    if link.startswith(("socks://", "socks5://")):
        return _parse_socks(link)
    if link.startswith(("http://", "https://")):
        return _parse_http(link)
    if re.search(r"=\s*ss\s*,", link, re.I):          # Surge 代理行: 名字 = ss, 服务器, 端口, encrypt-method=…, password=…
        return _parse_surge(link)
    raise ValueError("支持: ss:// / vmess:// / trojan:// / vless://(含 reality)/ hysteria2:// / tuic:// / "
                     "anytls:// / socks5:// / http:// 链接, 或 Surge 的 ss 行(名字 = ss, …)")

def _b64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore")

def _parse_ss(link):
    body = link[5:]; tag = ""
    if "#" in body:
        body, tag = body.split("#", 1); tag = urllib.parse.unquote(tag).strip()
    body = body.split("?", 1)[0]
    if "@" in body:
        ui, hp = body.rsplit("@", 1)
        try:
            method, pw = _b64(ui).split(":", 1)
        except Exception:
            method, pw = urllib.parse.unquote(ui).split(":", 1)
        host, port = hp.rsplit(":", 1)
    else:
        head, hp = _b64(body).rsplit("@", 1); method, pw = head.split(":", 1); host, port = hp.rsplit(":", 1)
    return {"type": "shadowsocks", "tag": _tag(tag, host.strip("[]"), port), "server": host.strip("[]"),
            "server_port": int(port.split("/")[0]), "method": method, "password": pw}

def _parse_surge(line):
    """Surge 代理行(目前支持 ss): 名字 = ss, 服务器, 端口, encrypt-method=…, password="…", tfo=true, udp-relay=true"""
    name, _, rest = line.partition("=")
    parts = [p.strip() for p in rest.split(",")]
    if not parts or parts[0].lower() != "ss":
        raise ValueError("Surge 行暂只支持 ss(其它类型请用 ss:// / vmess:// / trojan:// / vless:// 链接)")
    if len(parts) < 3:
        raise ValueError("Surge ss 行格式: 名字 = ss, 服务器, 端口, encrypt-method=…, password=…")
    server = parts[1].strip("[]"); port = int(parts[2].split("/")[0])
    kv = {}
    for p in parts[3:]:                               # key=value(password 里的 base64 可能含 = / +, 故只切第一个 =)
        if "=" in p:
            k, v = p.split("=", 1); kv[k.strip().lower()] = v.strip().strip('"').strip("'")
    method = kv.get("encrypt-method") or kv.get("method")
    pw = kv.get("password")
    if not method or not pw:
        raise ValueError("Surge ss 行缺 encrypt-method 或 password")
    out = {"type": "shadowsocks", "tag": _tag(name.strip(), server, str(port)),
           "server": server, "server_port": port, "method": method, "password": pw}
    if kv.get("tfo", "").lower() in ("true", "1"):
        out["tcp_fast_open"] = True
    return out

def _tls_block(server_name, insecure=False):
    b = {"enabled": True}
    if server_name:
        b["server_name"] = server_name
    if insecure:
        b["insecure"] = True
    return b

def _transport(net, host, path, service=None):
    if net in ("ws", "websocket"):
        t = {"type": "ws", "path": path or "/"}
        if host:
            t["headers"] = {"Host": host}
        return t
    if net == "grpc":                                 # 分享链接 grpc 服务名多在 serviceName=/service_name=, 不在 path
        return {"type": "grpc", "service_name": service or (path or "").lstrip("/")}
    return None

def _parse_vmess(link):
    j = json.loads(_b64(link[8:]))
    host, port = j["add"], int(j["port"])
    ob = {"type": "vmess", "tag": _tag(j.get("ps"), host, port), "server": host, "server_port": port,
          "uuid": j["id"], "alter_id": int(j.get("aid", 0) or 0), "security": j.get("scy") or "auto"}
    if str(j.get("tls", "")).lower() in ("tls", "true", "1"):
        ob["tls"] = _tls_block(j.get("sni") or j.get("host") or host)
    tr = _transport(j.get("net", "tcp"), j.get("host"), j.get("path"))
    if tr:
        ob["transport"] = tr
    return ob

def _qs(u):
    return {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}

def _parse_trojan(link):
    u = urllib.parse.urlparse(link); q = _qs(u)
    ob = {"type": "trojan", "tag": _tag(urllib.parse.unquote(u.fragment), u.hostname, u.port),
          "server": u.hostname, "server_port": u.port or 443, "password": urllib.parse.unquote(u.username or "")}
    ob["tls"] = _tls_block(q.get("sni") or q.get("peer") or u.hostname, q.get("allowInsecure") in ("1", "true"))
    tr = _transport(q.get("type", "tcp"), q.get("host"), q.get("path"),
                    q.get("serviceName") or q.get("service_name"))
    if tr:
        ob["transport"] = tr
    return ob

def _parse_vless(link):
    u = urllib.parse.urlparse(link); q = _qs(u)
    ob = {"type": "vless", "tag": _tag(urllib.parse.unquote(u.fragment), u.hostname, u.port),
          "server": u.hostname, "server_port": u.port or 443, "uuid": u.username, "flow": q.get("flow", "")}
    if not ob["flow"]:
        ob.pop("flow")
    sec = q.get("security")
    if sec in ("tls", "reality", "xtls"):
        ob["tls"] = _tls_block(q.get("sni") or u.hostname, q.get("allowInsecure") in ("1", "true"))
        if sec == "reality":                          # Reality: 公钥 pbk + short_id sid(+ 指纹 fp)
            ob["tls"]["reality"] = {"enabled": True, "public_key": q.get("pbk", ""), "short_id": q.get("sid", "")}
        if q.get("fp"):
            ob["tls"]["utls"] = {"enabled": True, "fingerprint": q["fp"]}
    tr = _transport(q.get("type", "tcp"), q.get("host"), q.get("path"),
                    q.get("serviceName") or q.get("service_name"))
    if tr:
        ob["transport"] = tr
    return ob

def _userinfo(u):
    """URI 用户信息整体取出(hysteria2/anytls 的 password 是单串, 但容错 user:pass 形式)。"""
    s = u.username or ""
    if u.password is not None:
        s += ":" + u.password
    return urllib.parse.unquote(s)

def _insec(q):
    return any(q.get(k) in ("1", "true") for k in ("insecure", "allowInsecure", "allow_insecure"))

def _parse_hysteria2(link):
    u = urllib.parse.urlparse(link); q = _qs(u)
    ob = {"type": "hysteria2", "tag": _tag(urllib.parse.unquote(u.fragment), u.hostname, u.port),
          "server": u.hostname, "server_port": u.port or 443, "password": _userinfo(u),
          "tls": _tls_block(q.get("sni") or q.get("peer") or u.hostname, _insec(q))}
    if q.get("obfs"):                                 # 通常是 salamander
        ob["obfs"] = {"type": q["obfs"], "password": q.get("obfs-password", "")}
    return ob

def _parse_tuic(link):
    u = urllib.parse.urlparse(link); q = _qs(u)
    ob = {"type": "tuic", "tag": _tag(urllib.parse.unquote(u.fragment), u.hostname, u.port),
          "server": u.hostname, "server_port": u.port or 443,
          "uuid": urllib.parse.unquote(u.username or ""), "password": urllib.parse.unquote(u.password or ""),
          "tls": _tls_block(q.get("sni") or u.hostname, _insec(q))}
    if q.get("alpn"):
        ob["tls"]["alpn"] = q["alpn"].split(",")
    if q.get("congestion_control"):
        ob["congestion_control"] = q["congestion_control"]
    if q.get("udp_relay_mode"):
        ob["udp_relay_mode"] = q["udp_relay_mode"]
    return ob

def _parse_anytls(link):
    u = urllib.parse.urlparse(link); q = _qs(u)
    return {"type": "anytls", "tag": _tag(urllib.parse.unquote(u.fragment), u.hostname, u.port),
            "server": u.hostname, "server_port": u.port or 443, "password": _userinfo(u),
            "tls": _tls_block(q.get("sni") or u.hostname, _insec(q))}

def _parse_socks(link):
    u = urllib.parse.urlparse(link)
    ob = {"type": "socks", "tag": _tag(urllib.parse.unquote(u.fragment), u.hostname, u.port),
          "server": u.hostname, "server_port": u.port or 1080, "version": "5"}
    user = urllib.parse.unquote(u.username) if u.username else None
    pw = urllib.parse.unquote(u.password) if u.password else None
    if user and pw is None and ":" not in user:       # socks5://base64(user:pass)@host:port 也常见
        try:
            d = _b64(user)
            if ":" in d:
                user, pw = d.split(":", 1)
        except Exception:  # noqa: BLE001
            pass
    if user:
        ob["username"] = user
    if pw:
        ob["password"] = pw
    return ob

def _parse_http(link):
    u = urllib.parse.urlparse(link)
    ob = {"type": "http", "tag": _tag(urllib.parse.unquote(u.fragment), u.hostname, u.port),
          "server": u.hostname, "server_port": u.port or (443 if u.scheme == "https" else 80)}
    if u.username:
        ob["username"] = urllib.parse.unquote(u.username)
    if u.password:
        ob["password"] = urllib.parse.unquote(u.password)
    if u.scheme == "https":
        ob["tls"] = _tls_block(u.hostname)
    return ob

# ── 故障切换组 (urltest) ──
def add_group(name, members):
    c = load(); cands = concrete_tags(c)
    members = [m for m in members if m]
    name = _tag(name, "", "")
    if name in cands:
        return False, f"组名 {name} 和现有出口冲突, 换个名字"
    bad = [m for m in members if m not in cands]
    if bad:
        return False, f"未知成员: {', '.join(bad)}\n只能用具体出口: {', '.join(cands)}"
    if len(members) < 2:
        return False, "故障切换组至少要 2 个出口"
    def mod(cc):
        for o in cc["outbounds"]:           # 已存在则原地改成员(保留在列表中的位置)
            if o.get("tag") == name and o.get("type") == "urltest":
                o["outbounds"] = members
                o.setdefault("url", DELAY_URL); o.setdefault("interval", "3m"); o.setdefault("tolerance", 50)
                return
        cc["outbounds"].append({"type": "urltest", "tag": name, "outbounds": members,
                                "url": DELAY_URL, "interval": "3m", "tolerance": 50})
    ok, msg = apply_sb(mod)
    return ok, (f"✅ 故障切换组 <b>{name}</b> = {' › '.join(members)}\n"
                "自动选最快, 成员故障自动切换。可在「🎯 设默认出口」或分流规则里选它。" if ok else msg)

# ── 直连表 (mosdns) ──
def _read_direct():
    if not os.path.exists(MOSDNS_DIRECT):
        return []
    return [l.strip().replace("domain:", "") for l in open(MOSDNS_DIRECT)
            if l.strip() and not l.startswith("#")]

def _write_direct(domains):
    with open(MOSDNS_DIRECT, "w") as f:
        f.write("# pdg-bot 自定义直连\n" + "".join("domain:" + d + "\n" for d in sorted(set(domains))))
    sh(["systemctl", "restart", "mosdns"])

# ── mosdns DNS 上游 (remote=国际 / local=国内; 用于接 DNS 解锁等自定义解析器) ──
def _upstreams(which):
    tag = which + "_upstream"
    try:
        lines = open(MOSDNS_CONF).read().splitlines()
    except Exception:  # noqa: BLE001
        return []
    for i, ln in enumerate(lines):
        if ln.strip() == f"- tag: {tag}":
            for j in range(i, min(i + 6, len(lines))):
                if "upstreams" in lines[j]:
                    return re.findall(r'addr:\s*"?([^",}\s]+)"?', lines[j])
    return []

def set_mosdns_upstream(which, addrs):
    if which not in ("remote", "local"):
        return False, "第一个词只能是 remote(国际) 或 local(国内)"
    addrs = [a.strip() for a in addrs if a.strip()]
    if not addrs:
        return False, "至少给一个 DNS 地址 (udp://1.2.3.4:53 / tcp://.. / https://x/dns-query / tls://..)"
    tag = which + "_upstream"
    try:
        lines = open(MOSDNS_CONF).read().splitlines()
    except Exception as e:  # noqa: BLE001
        return False, f"读 mosdns 配置失败: {e}"
    items = ", ".join('{addr: "%s"}' % a for a in addrs)
    done = False
    for i, ln in enumerate(lines):
        if ln.strip() == f"- tag: {tag}":
            for j in range(i, min(i + 6, len(lines))):
                if "upstreams" in lines[j]:
                    indent = lines[j][:len(lines[j]) - len(lines[j].lstrip())]
                    # 单上游=1(否则 mosdns 会对同一台并发查两次); 多上游=2 才有真故障转移(默认 1 不转移)
                    conc = 1 if len(addrs) == 1 else 2
                    lines[j] = indent + "args: { concurrent: %d, upstreams: [ %s ] }" % (conc, items)
                    done = True
                    break
        if done:
            break
    if not done:
        return False, f"没在 mosdns 配置里找到 {tag} 块"
    shutil.copy(MOSDNS_CONF, MOSDNS_CONF + ".botbak")
    with open(MOSDNS_CONF, "w") as f:
        f.write("\n".join(lines) + "\n")
    sh(["systemctl", "restart", "mosdns"])
    if sh(["systemctl", "is-active", "mosdns"]).stdout.strip() != "active":
        shutil.copy(MOSDNS_CONF + ".botbak", MOSDNS_CONF); sh(["systemctl", "restart", "mosdns"])
        return False, "mosdns 重启失败(配置可能不合法), 已回滚"
    return True, f"✅ {which} 上游已设为: {', '.join(addrs)}"

# ── 流媒体/服务解锁: 在「落地出口」与「WDA 解锁」之间整体切换 ──
# WDA 模式: 这些域名 → jp 直出 + 经 mosdns 用解锁 DNS(22.22.22.22)解析到中继(从本机授权 IP 出)。
# 落地模式: 不加规则, 这些域名回落到各自现有分流出口(hk/tw 等)。
# mosdns 侧的 unlock 支(unlock_upstream + geosite_unlock)是常驻的(install/迁移装好), 平时休眠;
# 本函数只在 WDA 模式把域名清单写进 mosdns 的 unlock.txt 与 mihomo 的 rule-provider, 并加 mihomo 路由规则。
MOSDNS_RULES = "/etc/mosdns/rules"
UNLOCK_DNS = "22.22.22.22"   # 解锁服务(WDA)的 DNS; 与 mosdns unlock_upstream 一致。换厂商需同步两处。
WDA_DOMAINS = [
    # 流媒体
    "netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net",
    "disneyplus.com", "disney-plus.net", "dssott.com", "bamgrid.com", "disneyplus.disney.co.jp",
    "primevideo.com", "aiv-cdn.net", "aiv-delivery.net", "amazonvideo.com", "pv-cdn.net",
    "tv.apple.com", "uts-api.itunes.apple.com", "play-edge.itunes.apple.com", "np-edge.itunes.apple.com",
    "youtube.com", "googlevideo.com", "ytimg.com", "youtu.be", "youtubei.googleapis.com", "yt3.ggpht.com",
    "dazn.com", "dazn-api.com", "indazn.com", "daznplayer.com",
    "unext.jp", "nxtv.jp", "iq.com", "iqiyi.com", "qy.net",
    "tvbanywhere.com", "mytvsuper.com", "dmm.com", "dmm.co.jp", "dmmapis.com",
    # AI
    "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
    "anthropic.com", "claude.ai", "gemini.google.com", "generativelanguage.googleapis.com",
    "aistudio.google.com", "meta.ai",
    # 其它(WDA JP 平台支持)
    "steampowered.com", "steamcommunity.com", "steamstatic.com", "play.google.com", "android.com",
]

def _wda_on(c=None):
    c = c or load()
    return any(r.get("rule_set") == "unlock" and r.get("outbound") == "jp"
               for r in c.get("route", {}).get("rules", []))

def _server_ip():
    """本机公网 IP(从 mihomo state 的 reject 规则取); 用于提示去解锁服务后台授权哪个 IP。"""
    try:
        for r in load().get("route", {}).get("rules", []):
            if r.get("action") == "reject":
                for x in r.get("ip_cidr", []):
                    if x.endswith("/32") and not x.startswith("127."):
                        return x.split("/")[0]
    except Exception:  # noqa: BLE001
        pass
    return "本机公网IP"

def _wda_authorized():
    """探测本机 IP 是否已在解锁服务后台授权: 解锁 DNS 对 Netflix 判别域名返回"中继"
    (与解锁 DNS 同 /24 的 IP)即已授权。没订阅/没加白/DNS 不通 → False。"""
    net24 = UNLOCK_DNS.rsplit(".", 1)[0] + "."
    out = sh(["dig", "+short", "+time=3", "+tries=2", "@" + UNLOCK_DNS, "nflxso.net", "A"]).stdout
    return any(ln.strip().startswith(net24) for ln in out.splitlines())

def _write_unlock_file(domains):
    """把 domains(可空)写进 mosdns unlock.txt(domain: 前缀); 变了才重启 mosdns(失败回滚)。
    空列表 = 落地模式: 清空文件 → mosdns 解锁支不命中任何域名 = 休眠(本机查询这些域名回落普通上游)。"""
    path = os.path.join(MOSDNS_RULES, "unlock.txt")
    want = "".join("domain:%s\n" % d for d in domains)
    try:
        cur = open(path).read()
    except OSError:
        cur = None
    if cur == want or (want == "" and not cur):
        return True, ""                       # 已是目标(含: 要清空且本来就空/无文件)
    if domains:                               # 只有"写域名"才要求 mosdns 已有解锁支
        try:
            if "unlock_upstream" not in open(MOSDNS_CONF).read():
                return False, "mosdns 还没有解锁支(unlock_upstream)。请先在服务器跑  sudo pdg update  补上再切。"
        except OSError as e:
            return False, f"读 mosdns 配置失败: {e}"
    os.makedirs(MOSDNS_RULES, exist_ok=True)
    if cur is not None:
        shutil.copy(path, path + ".bak")
    open(path, "w").write(want)
    sh(["systemctl", "restart", "mosdns"]); time.sleep(1)
    if sh(["systemctl", "is-active", "mosdns"]).stdout.strip() != "active":
        if os.path.exists(path + ".bak"):
            shutil.copy(path + ".bak", path)
        sh(["systemctl", "restart", "mosdns"])
        return False, "mosdns 重启失败, 已回滚 unlock.txt"
    return True, ""

def set_wda_mode(on):
    was_on = _wda_on()                          # 记下操作前状态: 回滚要还原到它, 而不是无脑清空
    if on:
        if not _wda_authorized():               # 没授权就开 = 流媒体走 jp 直出但拿不到中继, 反而更糟 → 先拦住
            ip = _server_ip()
            return False, ("⚠️ 没在解锁 DNS(%s)上测到本机的中继, <b>先别开 WDA</b>(否则解锁服务拿不到中继, 流媒体反而可能挂)。\n"
                           "常见原因: 没订阅解锁服务 / 没在服务商<b>后台把本机公网 IP <code>%s</code> 加白授权</b> / DNS 不通。\n"
                           "→ 去服务商后台授权本机 IP <code>%s</code>, 再点 🔓。(未改动, 仍走落地出口)"
                           % (UNLOCK_DNS, ip, ip))
        ok, err = _write_unlock_file(WDA_DOMAINS)   # mosdns 侧: 写满解锁清单
        if not ok:
            return False, err
        os.makedirs(RS_DIR, exist_ok=True)
        with open(os.path.join(RS_DIR, "unlock.yaml"), "w") as f:
            f.write("payload:\n")
            for d in WDA_DOMAINS:
                f.write("  - DOMAIN-SUFFIX," + d + "\n")
    def mod(c):
        c["route"].setdefault("rule_set", [])
        c["route"]["rule_set"] = [r for r in c["route"]["rule_set"] if r.get("tag") != "unlock"]
        c["route"]["rules"] = [r for r in c["route"]["rules"] if r.get("rule_set") != "unlock"]
        if on:
            c["route"]["rule_set"].append({"tag": "unlock", "type": "local", "format": "source",
                                           "path": os.path.join(RS_DIR, "unlock.json")})
            idx = 1 if c["route"]["rules"] and c["route"]["rules"][0].get("action") == "reject" else 0
            c["route"]["rules"].insert(idx, {"rule_set": "unlock", "outbound": "jp"})
    ok, msg = apply_sb(mod)
    if not ok:
        if on and not was_on:                    # 仅"本来关→这次想开"失败才清回空; 本来就开则 apply_sb 已还原成带规则的旧配置, 保持 unlock.txt
            okc, errc = _write_unlock_file([])
            if not okc:                          # 连回滚清空都失败 → 别静默, 明确告知 mosdns 侧可能残留
                msg += "\n⚠️ 且回滚清空 unlock.txt 也失败(" + errc + "): mosdns 侧可能仍残留解锁清单, 请重试或手动清空。"
        return False, msg
    if on:
        return True, ("✅ 已切到【🔓 WDA 解锁】: %d 个域名走 WDA(jp 直出 + 22.22.22.22 中继)。\n"
                      "其余流量照常分流。哪个服务在 WDA 下不灵, 切回【落地出口】即可。") % len(WDA_DOMAINS)
    # 关闭: mihomo 规则已撤; 再清空 mosdns unlock.txt, 让解锁支彻底休眠(否则本机解析这些域名仍走解锁 DNS)
    okc, errc = _write_unlock_file([])
    if okc:
        return True, "✅ 已切到【🛬 落地出口】: 解锁域名回落各自出口(hk/tw), mosdns 解锁清单已清空。"
    return True, ("✅ 已切到【🛬 落地出口】(mihomo 规则已撤)。\n"
                  "⚠️ 但清空 mosdns unlock.txt 失败(" + errc + "): 本机解析这些域名可能仍走解锁 DNS, 可再点一次 🛬 或手动清空。")

# ── TCP Fast Open ──
def _tfo_on(c):
    obs = [o for o in c["outbounds"] if o.get("type") in PROXY_TYPES]
    return bool(obs) and all(o.get("tcp_fast_open") for o in obs)

def set_tfo(on):
    def mod(c):
        for o in c["outbounds"]:
            if o.get("type") in PROXY_TYPES:
                if on:
                    o["tcp_fast_open"] = True
                else:
                    o.pop("tcp_fast_open", None)
        for i in c.get("inbounds", []):
            if on:
                i["tcp_fast_open"] = True
            else:
                i.pop("tcp_fast_open", None)
    ok, msg = apply_sb(mod)
    if ok and on:
        sh(["sysctl", "-w", "net.ipv4.tcp_fastopen=3"])
        try:
            with open("/etc/sysctl.d/99-pdg-tfo.conf", "w") as f:
                f.write("net.ipv4.tcp_fastopen=3\n")
        except Exception:  # noqa: BLE001
            pass
    return ok, ((f"✅ TFO 已{'开启' if on else '关闭'}(出口+入口)\n"
                 "降到落地的握手延迟; 需落地端也支持, 否则自动回落普通握手。") if ok else msg)

# ── 规则集 (Surge .list -> mihomo classical rule-provider) ──
def _rs_meta():
    if os.path.exists(RS_META):
        return json.load(open(RS_META))
    return {}

def _save_rs_meta(m):
    os.makedirs(os.path.dirname(RS_META), exist_ok=True)
    json.dump(m, open(RS_META, "w"), ensure_ascii=False, indent=2)

def _parse_surge_rules(text):
    dom, suf, kw, ip = [], [], [], []
    # Accept normal line-oriented lists and compact one-line lists such as
    # public APNs sources, where comments and rule tokens share a line.
    token = re.compile(
        r"(?<![A-Za-z0-9_-])(DOMAIN-SUFFIX|DOMAIN-KEYWORD|DOMAIN|IP-CIDR6?|"
        r"DOMAIN-WILDCARD)\s*,\s*([^\s,#]+)(?:\s*,\s*([^\s,#]+))?",
        re.IGNORECASE,
    )
    matches = token.findall(str(text))
    if matches:
        for typ, value, _option in matches:
            typ = typ.upper()
            if typ == "DOMAIN":
                dom.append(value)
            elif typ == "DOMAIN-SUFFIX":
                suf.append(value)
            elif typ == "DOMAIN-KEYWORD":
                kw.append(value)
            elif typ in ("IP-CIDR", "IP-CIDR6"):
                ip.append(value)
        return dom, suf, kw, ip
    for line in text.splitlines():
        line = line.split("#", 1)[0].split("//", 1)[0].strip()
        if not line:
            continue
        p = [x.strip() for x in line.split(",")]
        t = p[0].upper()
        if t == "DOMAIN" and len(p) > 1:
            dom.append(p[1])
        elif t == "DOMAIN-SUFFIX" and len(p) > 1:
            suf.append(p[1])
        elif t == "DOMAIN-KEYWORD" and len(p) > 1:
            kw.append(p[1])
        elif t in ("IP-CIDR", "IP-CIDR6") and len(p) > 1:
            ip.append(p[1])
    return dom, suf, kw, ip


def _fetch_surge(url):
    req = urllib.request.Request(url, headers={"User-Agent": "pdg-bot"})
    with urllib.request.urlopen(req, timeout=30) as r:
        text = r.read().decode("utf-8", "ignore")
    return _parse_surge_rules(text)

def _fetch_bytes(url):
    req = urllib.request.Request(url, headers={"User-Agent": "pdg-bot"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()

def _build_source(url, path):
    """下载 Surge/Clash 文本 → 写 mihomo classical rule-provider。返回 (条数, 是否纯IP)。"""
    dom, suf, kw, ip = _fetch_surge(url)
    if not (dom or suf or kw or ip):
        raise ValueError("没解析出规则(支持 DOMAIN/-SUFFIX/-KEYWORD/IP-CIDR)")
    payload = []
    payload += [f"DOMAIN,{x}" for x in dom]
    payload += [f"DOMAIN-SUFFIX,{x}" for x in suf]
    payload += [f"DOMAIN-KEYWORD,{x}" for x in kw]
    payload += [f"{'IP-CIDR6' if ':' in x else 'IP-CIDR'},{x}" for x in ip]
    with open(path, "w") as f:
        f.write("payload:\n")
        for item in payload:
            f.write("  - " + item + "\n")
    return len(dom) + len(suf) + len(kw) + len(ip), (len(dom) + len(suf) + len(kw) == 0)

def _force_gateway_domain_lines(c=None):
    """Extract exact/suffix domains from rule sets marked force_gateway.

    IP entries remain in the Mihomo provider; only domain entries can steer DNS
    to the gateway before the normal China/Apple direct list.
    """
    c = load() if c is None else c
    force_tags = {str(r.get("rule_set")) for r in c.get("route", {}).get("rules", [])
                  if r.get("force_gateway") and r.get("rule_set")}
    if not force_tags:
        return []
    meta = _rs_meta()
    lines = set()
    for tag in sorted(force_tags):
        info = next((item for item in c.get("route", {}).get("rule_set", [])
                     if item.get("tag") == tag), {})
        path = info.get("path") or meta.get(tag, {}).get("path")
        path = path or os.path.join(RS_DIR, tag + ".yaml")
        if not str(path).startswith(RS_DIR + "/"):
            raise ValueError(f"强制引流规则集路径不安全: {tag}")
        if not os.path.exists(path):
            raise ValueError(f"强制引流规则集文件缺失: {tag}")
        for raw in open(path, encoding="utf-8"):
            item = raw.strip()
            if item.startswith("- "):
                item = item[2:].strip().strip('"').strip("'")
            fields = [field.strip() for field in item.split(",")]
            if len(fields) < 2:
                continue
            kind = fields[0].upper()
            if kind == "DOMAIN":
                lines.add("full:" + _adblock_hostname(fields[1]))
            elif kind == "DOMAIN-SUFFIX":
                lines.add("domain:" + _adblock_hostname(fields[1].lstrip("+.")))
    if force_tags and not lines:
        raise ValueError("强制引流规则集没有可用于 DNS 的域名规则")
    return sorted(lines)


def _write_force_gateway_domains(c=None, restart=True):
    try:
        lines = _force_gateway_domain_lines(c)
    except (OSError, ValueError) as exc:
        return False, str(exc)
    want = ("\n".join(lines) + "\n") if lines else ""
    try:
        previous = open(MOSDNS_FORCE_PROXY, "rb").read()
    except OSError:
        previous = None
    if previous == want.encode():
        return True, ""
    os.makedirs(os.path.dirname(MOSDNS_FORCE_PROXY), mode=0o755, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".force-proxy-",
                                     dir=os.path.dirname(MOSDNS_FORCE_PROXY), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(want)
            file.flush(); os.fsync(file.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, MOSDNS_FORCE_PROXY)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    if not restart:
        return True, ""
    result = sh(["systemctl", "restart", "mosdns"])
    if result.returncode == 0 and sh(["systemctl", "is-active", "mosdns"]).stdout.strip() == "active":
        return True, ""
    if previous is None:
        try:
            os.unlink(MOSDNS_FORCE_PROXY)
        except OSError:
            pass
    else:
        with open(MOSDNS_FORCE_PROXY, "wb") as file:
            file.write(previous)
    sh(["systemctl", "restart", "mosdns"])
    return False, "mosdns 强制引流域名更新失败，已回滚"


def add_ruleset(url, target, label="", force_gateway=False):
    c = load()
    if target not in exit_tags(c):
        return False, f"出口 {target} 不存在; 可选: {', '.join(exit_tags(c))}"
    if force_gateway and not _force_proxy_mosdns_ready():
        return False, "mosdns 尚未安装强制网关分支，请先运行 sudo pdg update"
    low = url.lower().split("?", 1)[0]
    if low.endswith((".mrs", ".srs")):
        return False, "bot 目前只解析 .list/.txt 文本规则集；.mrs/.srs 可手写到 /etc/mihomo/config.yaml，但不会被 bot 管理。"
    name = "rs_" + hashlib.sha1(url.encode()).hexdigest()[:8]
    os.makedirs(RS_DIR, exist_ok=True)
    previous_state = json.loads(json.dumps(c))
    previous_meta = json.loads(json.dumps(_rs_meta()))
    provider_path = os.path.join(RS_DIR, name + ".yaml")
    previous_provider = None
    if os.path.exists(provider_path):
        try:
            previous_provider = open(provider_path, "rb").read()
        except OSError:
            previous_provider = None
    try:
        path = os.path.join(RS_DIR, name + ".yaml"); fmt = "classical"
        count, ip_only = _build_source(url, path)
        if force_gateway and not _force_gateway_domain_lines({
                **c, "route": {**c.get("route", {}), "rule_set": [
                    *c.get("route", {}).get("rule_set", []),
                    {"tag": name, "path": path}],
                "rules": [*c.get("route", {}).get("rules", []),
                          {"rule_set": name, "force_gateway": True}],
        }}):
            raise ValueError("强制引流规则集没有可用于 DNS 的域名规则")
        warn = ("\n⚠️ 纯 IP 规则集: 透明代理能看到 IP 连接, 但无域名的 App 仍可能无法被精确分流。"
                if ip_only else "")
    except Exception as e:  # noqa: BLE001
        return False, f"下载/解析失败: {e}"

    def mod(cc):
        cc["route"].setdefault("rule_set", [])
        cc["route"]["rule_set"] = [r for r in cc["route"]["rule_set"] if r.get("tag") != name]
        cc["route"]["rule_set"].append({"tag": name, "type": "local", "format": fmt,
                                          "path": path, **({"force_gateway": True} if force_gateway else {})})
        cc["route"]["rules"] = [r for r in cc["route"]["rules"] if r.get("rule_set") != name]
        idx = 1 if cc["route"]["rules"] and cc["route"]["rules"][0].get("action") == "reject" else 0
        cc["route"]["rules"].insert(idx, {
            "rule_set": name, "outbound": target,
            **({"force_gateway": True} if force_gateway else {}),
        })
    ok, msg = apply_sb(mod)
    if ok:
        m = _rs_meta(); m[name] = {"url": url, "outbound": target, "format": fmt,
                                   "path": path, "count": count,
                                   **({"force_gateway": True} if force_gateway else {})}
        if label.strip():
            m[name]["label"] = label.strip()[:40]
        _save_rs_meta(m)
        if force_gateway:
            synced, sync_msg = _write_force_gateway_domains(load())
            if not synced:
                def restore(cc):
                    cc.clear(); cc.update(previous_state)
                apply_sb(restore)
                if previous_provider is None:
                    try:
                        os.remove(provider_path)
                    except OSError:
                        pass
                else:
                    with open(provider_path, "wb") as file:
                        file.write(previous_provider)
                _save_rs_meta(previous_meta)
                return False, sync_msg
        cntdesc = f"{count} 条"
        mode = "；已加入强制网关透明转发" if force_gateway else ""
        return True, f"规则集已添加 → {target}（{cntdesc}，{label.strip() or name}）" + mode + warn
    return False, msg

def set_ruleset_label(name, label):
    """给规则集设个看得懂的显示名(备注), 只改 bot 显示, 不动 mihomo 内部 tag/文件。"""
    m = _rs_meta()
    if name not in m:
        return False, "规则集不存在(可能已删), 重开列表再试"
    label = label.strip()[:40]
    if label:
        m[name]["label"] = label
    else:
        m[name].pop("label", None)
    _save_rs_meta(m)
    return True, f"✅ 规则集名称已设为「{label or name}」"

def _rs_items():
    """[(name, 显示文字)] 供选择键盘用。"""
    return [(n, (i.get("label") or n) + f" · {i.get('count', '?')}条") for n, i in _rs_meta().items()]

def del_ruleset(name):
    m = _rs_meta(); info = m.get(name, {}); path = info.get("path")
    current = load()
    force_gateway = any(r.get("rule_set") == name and r.get("force_gateway")
                        for r in current.get("route", {}).get("rules", []))
    previous_meta = json.loads(json.dumps(m))
    label = info.get("label") or name              # 删前取显示名(删完 meta 就没了)
    desired = json.loads(json.dumps(current))
    desired["route"]["rule_set"] = [r for r in desired["route"].get("rule_set", [])
                                      if r.get("tag") != name]
    desired["route"]["rules"] = [r for r in desired["route"]["rules"]
                                   if r.get("rule_set") != name]
    if force_gateway:
        synced, sync_msg = _write_force_gateway_domains(desired)
        if not synced:
            return False, sync_msg
    def mod(cc):
        cc["route"]["rule_set"] = [r for r in cc["route"].get("rule_set", []) if r.get("tag") != name]
        cc["route"]["rules"] = [r for r in cc["route"]["rules"] if r.get("rule_set") != name]
    ok, msg = apply_sb(mod)
    if ok:
        m.pop(name, None); _save_rs_meta(m)
        for p in (path, os.path.join(RS_DIR, name + ".yaml")):
            try:
                if p:
                    os.remove(p)
            except OSError:
                pass
        return True, f"已删除规则集 {label}"
    if force_gateway:
        _write_force_gateway_domains(current)
        _save_rs_meta(previous_meta)
    return False, msg

def refresh_rulesets():
    """重下并原子替换所有规则集; mihomo test 通过才重启, 坏档自动回滚、不断网(供 bot 与每日定时调用)。"""
    m = _rs_meta(); n = 0; swapped = []   # (path, bak)
    for name, info in m.items():
        # 兼容早期缺 format/path 的旧条目 (按 name 回填, 否则刷新会 KeyError)。
        info.setdefault("format", "classical")
        info.setdefault("path", os.path.join(RS_DIR, name + ".yaml"))
        if not str(info["path"]).startswith(RS_DIR + "/"):
            info["path"] = os.path.join(RS_DIR, name + ".yaml")
        tmp = info["path"] + ".new"
        try:
            info["count"] = _build_source(info["url"], tmp)[0]   # 先写临时文件
            n += 1
        except Exception as e:  # noqa: BLE001
            print("refresh rs", name, e)
            try:
                os.remove(tmp)
            except OSError:
                pass
    # 原子替换(留 .bak 以便整体回滚)
    for name, info in m.items():
        tmp = info["path"] + ".new"
        if not os.path.exists(tmp):
            continue
        if os.path.exists(info["path"]):
            shutil.copy(info["path"], info["path"] + ".bak")
            swapped.append((info["path"], info["path"] + ".bak"))
        os.replace(tmp, info["path"])
    if n == 0:
        return 0
    if sh(["mihomo", "-t", "-d", os.path.dirname(MIHOMO_CFG)]).returncode != 0:   # 坏档 → 回滚, 不重启(不断网)
        for path, bak in swapped:
            shutil.copy(bak, path)
        print("refresh rs: mihomo test 失败, 已回滚, 不重启")
        return 0
    # 先重启加载新规则集, 确认 mihomo 真的 active 再删 .bak; 起不来则还原旧规则集重启, 不断网。
    sh(["systemctl", "reset-failed", "mihomo"]); sh(["systemctl", "restart", "mihomo"])
    if not _svc_active("mihomo"):
        for path, bak in swapped:
            shutil.copy(bak, path)        # 还原旧规则集
        sh(["systemctl", "reset-failed", "mihomo"]); sh(["systemctl", "restart", "mihomo"])
        if _svc_active("mihomo"):       # 确认旧服务真的恢复, 再清备份
            for _, bak in swapped:
                try:
                    os.remove(bak)
                except OSError:
                    pass
            print("refresh rs: 新规则集致 mihomo 起不来, 已还原旧规则集并恢复")
        else:                             # 连旧档都起不来 → 保留 .bak 备查, 不再删
            print("refresh rs: 还原旧规则集后仍未 active, 保留 .bak 备查")
        return 0
    try:
        synced, sync_msg = _write_force_gateway_domains(load())
    except Exception as exc:  # noqa: BLE001
        synced, sync_msg = False, str(exc)
    if not synced:
        for path, bak in swapped:
            shutil.copy(bak, path)
        sh(["systemctl", "reset-failed", "mihomo"]); sh(["systemctl", "restart", "mihomo"])
        print("refresh rs: 强制网关域名同步失败, 已回滚: " + sync_msg)
        return 0
    for _, bak in swapped:                 # 确认 active 后再清备份
        try:
            os.remove(bak)
        except OSError:
            pass
    _save_rs_meta(m)
    return n

# ── 测出口 (端到端延迟, clash_api; TCP 兜底) ──
def _test_exits_tcp(c):
    obs = proxy_outbounds(c)
    if not obs:
        return "(无代理出口)"
    lines = []
    for o in obs:
        host = o.get("server"); port = int(o.get("server_port", 0) or 0)
        try:
            t0 = time.monotonic()
            with socket.create_connection((host, port), timeout=5):
                ms = int((time.monotonic() - t0) * 1000)
            lines.append(f"✅ <b>{o['tag']}</b>  {ms}ms  ({o['type']} {host}:{port})")
        except Exception:  # noqa: BLE001
            lines.append(f"❌ <b>{o['tag']}</b>  不通  ({host}:{port})")
    return "出口连通/延迟 (JP→落地 TCP 握手):\n" + "\n".join(lines)

def test_exits():
    c = load()
    if not clash_up():
        return _test_exits_tcp(c)
    tags = concrete_tags(c)   # 只测具体出口(代理+jp直出); urltest 组的 clash 延迟接口偶尔抽风, 不测它
    if not tags:
        return "(无出口)"
    lines = []
    for t in tags:
        q = urllib.parse.quote(t, safe="")
        try:
            d = clash_get(f"/proxies/{q}/delay?timeout=5000&url=" + urllib.parse.quote(DELAY_URL))
            lines.append(f"✅ <b>{t}</b>  {d['delay']}ms")
        except urllib.error.HTTPError:
            lines.append(f"❌ <b>{t}</b>  超时/不通")
        except Exception:  # noqa: BLE001
            lines.append(f"❌ <b>{t}</b>  不通")
    return "出口端到端延迟 (经各出口→generate_204):\n" + "\n".join(lines)

# ── 流量统计 (clash_api) ──
def _fmt_bytes(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return (f"{n:.0f}{u}" if u == "B" else f"{n:.1f}{u}")
        n /= 1024
    return f"{n:.1f}PB"

def _vnstat():
    """网卡真实累计(vnstat, 重启/重启动不丢): 今日/本月/累计 ↓rx ↑tx。"""
    try:
        f = sh(["vnstat", "--oneline"]).stdout.strip().split(";")
        if len(f) >= 15:
            return (f"今日 ↓{f[3]} ↑{f[4]}\n本月 ↓{f[8]} ↑{f[9]}\n累计 ↓{f[12]} ↑{f[13]}")
    except Exception:  # noqa: BLE001
        pass
    return ""

def traffic_text():
    parts = []
    # 实时: clash_api —— 当前连接 + 「本会话」(mihomo 启动以来)经代理流量, mihomo 重启即清零
    if clash_up():
        try:
            d = clash_get("/connections")
            conns = d.get("connections") or []
            cnt, up, dn = Counter(), Counter(), Counter()
            for cn in conns:
                tag = (cn.get("chains") or ["?"])[0]
                cnt[tag] += 1; up[tag] += cn.get("upload", 0); dn[tag] += cn.get("download", 0)
            lines = [f"• <b>{t}</b>: {cnt[t]}条 ↑{_fmt_bytes(up[t])} ↓{_fmt_bytes(dn[t])}"
                     for t, _ in cnt.most_common()]
            parts.append("📈 <b>实时(mihomo 本会话, 重启清零)</b>\n"
                         f"会话累计 ↑{_fmt_bytes(d.get('uploadTotal'))} ↓{_fmt_bytes(d.get('downloadTotal'))}\n"
                         f"活跃连接 {len(conns)}" + ("\n" + "\n".join(lines) if lines else ""))
        except Exception as e:  # noqa: BLE001
            parts.append(f"实时读取失败: {e}")
    v = _vnstat()
    parts.append("📊 <b>总用量(vnstat·网卡真实)</b>\n" + v if v
                 else "📊 总用量: vnstat 暂无数据")
    return "\n\n".join(parts)

def doctor_text():
    """跑共用检查库(checks.ALL), 和 `pdg doctor` 同一套, 在手机上一键自检。"""
    try:
        import checks
        results = checks.run()
    except Exception as e:  # noqa: BLE001
        return f"🩺 自检失败: {e}"
    icon = {"ok": "🟢", "warn": "🟡", "fail": "🔴"}
    nf = sum(1 for l, _, _ in results if l == "fail")
    nw = sum(1 for l, _, _ in results if l == "warn")
    head = "🔴 有问题" if nf else ("🟡 有警告" if nw else "🟢 全部正常")
    lines = [f"{icon.get(l, '⚪️')} <b>{lb}</b>: {d}" for l, lb, d in results]
    tip = "\n\n出问题时排查见 docs/TROUBLESHOOTING-PLAYBOOK.md" if (nf or nw) else ""
    return (f"🩺 <b>自检</b> — {head}  ({nf} 失败 / {nw} 警告 / 共 {len(results)})\n\n"
            + "\n".join(lines) + tip)

# ── 更新(检查 → 确认 → 后台执行)──
PDG_REPO = "/opt/privdns-gateway"

def _esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def _git(*args, t=60):
    return subprocess.run(["git", "-C", PDG_REPO, *args], capture_output=True, text=True, timeout=t)

def _fetch_release_tags():
    r = _git("fetch", "-q", "--tags", "origin", "main", t=120)
    if r.returncode != 0:
        return False, (r.stderr or r.stdout or "git fetch 失败").strip()
    shallow = _git("rev-parse", "--is-shallow-repository")
    if shallow.stdout.strip() == "true":
        r = _git("fetch", "-q", "--unshallow", "--tags", "origin", "main", t=180)
        if r.returncode != 0:
            return False, (r.stderr or r.stdout or "git fetch --unshallow 失败").strip()
    return True, ""

def update_check():
    """检查是否有更新的发布 tag(只跟 tag, 不拉 main 中间提交)。返回 (有更新?, 文本)。"""
    try:
        ok, err = _fetch_release_tags()
        if not ok:
            return False, f"检查更新失败: {err}"
        cur = _git("describe", "--tags", "--always").stdout.strip()
        tags = _git("tag", "-l", "v*", "--sort=-v:refname").stdout.split()
    except Exception as e:  # noqa: BLE001
        return False, f"检查更新失败: {e}"
    if not tags:
        return False, "🟢 仓库还没有发布 tag。"
    tgt = tags[0]
    head = _git("rev-parse", "HEAD").stdout.strip()
    tcommit = _git("rev-parse", tgt + "^{commit}").stdout.strip()
    if head == tcommit:
        return False, f"🟢 已是最新发布 <b>{tgt}</b>。"
    mb = _git("merge-base", "--is-ancestor", "HEAD", tgt)
    if mb.returncode == 0:
        pass
    elif mb.returncode == 1:
        return False, f"🟢 已是最新(当前 <code>{cur}</code> 不落后于最新发布 {tgt})。"
    else:
        return False, f"检查更新失败: merge-base 判断失败: {(mb.stderr or mb.stdout).strip()}"
    log = _git("log", "--oneline", "HEAD.." + tgt).stdout.strip()
    n = len(log.splitlines())
    return True, (f"🔄 有新发布 <b>{tgt}</b>(当前 <code>{cur}</code>,含 {n} 个提交):\n"
                  f"<pre>{_esc(log)}</pre>\n确认后后台执行 pdg update → 更新到 {tgt}(约 30-60 秒, bot 自动重启回来)。")

def start_update():
    """在独立的 systemd 瞬时单元里跑 pdg update, 不受 pdg-bot 自身重启影响。"""
    try:
        r = subprocess.run(["systemd-run", "--collect", "/usr/local/bin/pdg", "update"],
                           capture_output=True, text=True, timeout=15)
        return r.returncode == 0
    except Exception:  # noqa: BLE001
        return False

# ── 单条规则增删 ──
def add_rule(domain, target):
    domain = domain.strip().lstrip(".").lower()
    if not re.match(r"^[a-z0-9.-]+$", domain):
        return False, "域名格式不对"
    if target in ("direct", "直连"):
        _write_direct(_read_direct() + [domain]); return True, f"已把 {domain} 设为直连"
    c = load()
    if target not in exit_tags(c):
        return False, f"出口 {target} 不存在; 可选: {', '.join(exit_tags(c))} 或 direct"

    def mod(cc):
        for r in cc["route"]["rules"]:
            if r.get("outbound") == target and "rule_set" not in r:
                r.setdefault("domain_suffix", [])
                if domain not in r["domain_suffix"]:
                    r["domain_suffix"].append(domain)
                return
        idx = 1 if cc["route"]["rules"] and cc["route"]["rules"][0].get("action") == "reject" else 0
        cc["route"]["rules"].insert(idx, {"domain_suffix": [domain], "outbound": target})
    ok, msg = apply_sb(mod)
    return ok, (f"已把 {domain} → {target}" if ok else msg)

def del_rule(domain):
    domain = domain.strip().lstrip(".").lower(); removed = []
    c = load()
    if any(domain in r.get(k, []) for r in c["route"]["rules"] for k in ("domain_suffix", "domain")):
        def mod(cc):
            for r in cc["route"]["rules"]:
                for k in ("domain_suffix", "domain"):
                    if domain in r.get(k, []):
                        r[k] = [d for d in r[k] if d != domain]
            cc["route"]["rules"] = [r for r in cc["route"]["rules"]
                                    if r.get("action") or "outbound" not in r or r.get("rule_set")
                                    or r.get("domain_suffix") or r.get("domain")
                                    or r.get("domain_keyword") or r.get("ip_cidr")]
        apply_sb(mod); removed.append("出口规则")
    if domain in _read_direct():
        _write_direct([d for d in _read_direct() if d != domain]); removed.append("直连表")
    return (bool(removed), f"已删除 {domain} ({'+'.join(removed)})" if removed else f"未找到含 {domain} 的规则")

def deletable_domains():
    """可删的单域名规则: [(域名, 显示文字)]。含各出口的 domain(_suffix) 与自定义直连表。"""
    c = load(); items = []
    for r in c["route"]["rules"]:
        if "outbound" not in r or r.get("rule_set"):
            continue
        for d in r.get("domain_suffix", []) + r.get("domain", []):
            items.append((d, f"{d} → {r['outbound']}"))
    for d in _read_direct():
        items.append((d, f"{d}(直连)"))
    return items

def del_rules_bulk(domains):
    """一次删除多个域名(出口规则 + 直连表), 只重启一次 mihomo。"""
    domains = {d.strip().lower() for d in domains if d.strip()}
    if not domains:
        return False, "没勾选任何域名"
    def mod(cc):
        for r in cc["route"]["rules"]:
            for k in ("domain_suffix", "domain"):
                if r.get(k):
                    r[k] = [d for d in r[k] if d not in domains]
        cc["route"]["rules"] = [r for r in cc["route"]["rules"]
                                if r.get("action") or "outbound" not in r or r.get("rule_set")
                                or r.get("domain_suffix") or r.get("domain")
                                or r.get("domain_keyword") or r.get("ip_cidr")]
    ok, msg = apply_sb(mod)
    if not ok:
        return False, msg
    cur = _read_direct(); hit = [x for x in cur if x in domains]
    if hit:
        _write_direct([x for x in cur if x not in domains])   # 直连表改 mosdns 文件(与原 del_rule 一致, 不重启 mosdns)
    return True, f"✅ 已删除 {len(domains)} 个域名" + (f"(含直连 {len(hit)} 个)" if hit else "")

def del_rule_kb(chat, back=RULE_BACK):
    """删规则多选键盘: 勾选/取消, 底部确认删除(N)。"""
    items = deletable_domains()
    valid = {d for d, _ in items}
    sel = del_sel.setdefault(chat, set()) & valid
    del_sel[chat] = sel
    rows = []
    for d, lbl in items[:80]:
        if len(("dtog:" + d).encode()) > 64:
            continue
        rows.append([{"text": ("☑️ " if d in sel else "⬜️ ") + lbl, "callback_data": "dtog:" + d}])
    rows.append([{"text": f"✅ 确认删除 ({len(sel)})", "callback_data": "ddel"}])
    rows.extend(_back_rows(back))
    return items, {"inline_keyboard": rows}

# ── 改分流规则出口 / 出口排序 / 改故障组 ──
def editable_rules(c):
    """可改出口的规则: [(索引, 简短标签)]。含域名规则与规则集规则。"""
    out = []; meta = _rs_meta()
    for i, r in enumerate(c["route"]["rules"]):
        if "outbound" not in r:
            continue
        if r.get("rule_set"):
            name = meta.get(r["rule_set"], {}).get("label") or r["rule_set"]   # 用显示名(改过名的), 没有才回退 rs_xxxx
            out.append((i, f'{r["outbound"]}: 规则集 {name}'))
        else:
            doms = r.get("domain_suffix", []) + r.get("domain", [])
            if doms:
                out.append((i, f'{r["outbound"]}: ' + ", ".join(doms[:4]) + (" …" if len(doms) > 4 else "")))
    return out

def _merge_domain_rules(rules):
    """同一出口的多条域名规则合并为一条, 保持其余规则顺序。"""
    seen = {}; out = []
    for r in rules:
        if r.get("outbound") and "rule_set" not in r and (r.get("domain_suffix") or r.get("domain")):
            t = r["outbound"]
            if t in seen:
                base = seen[t]
                for k in ("domain_suffix", "domain"):
                    if r.get(k):
                        base.setdefault(k, [])
                        base[k] += [x for x in r[k] if x not in base[k]]
                continue
            seen[t] = r
        out.append(r)
    return out

def reassign_rule(idx, target):
    c = load(); rules = c["route"]["rules"]
    if idx < 0 or idx >= len(rules) or "outbound" not in rules[idx]:
        return False, "该规则已变动, 请重开列表再试"
    if target not in exit_tags(c):
        return False, f"出口 {target} 不存在"
    old = rules[idx]["outbound"]
    if old == target:
        return True, f"已经是 {target}, 未改动"
    def mod(cc):
        cc["route"]["rules"][idx]["outbound"] = target
        cc["route"]["rules"] = _merge_domain_rules(cc["route"]["rules"])
    ok, msg = apply_sb(mod)
    return ok, (f"✅ 该规则出口 {old} → {target}" if ok else msg)

def reorder_exits(order):
    c = load(); allt = [o["tag"] for o in c["outbounds"]]
    order = [t for t in order if t]
    if set(order) != set(allt):
        return False, f"必须且只能列全部出口(空格分隔): {', '.join(allt)}"
    def mod(cc):
        cc["outbounds"].sort(key=lambda o: order.index(o["tag"]))
    ok, msg = apply_sb(mod)
    return ok, (f"✅ 出口顺序已更新: {' › '.join(order)}" if ok else msg)


def rename_exit(old, new):
    """真改名: 改 outbound 的 tag, 并级联更新全部引用 —— 分流规则(含 TG 出口规则)、
    故障组成员、route.final、规则集元数据的 outbound 记录。direct(模板锚点, WDA 依赖其 tag)不可改。"""
    c = load()
    if old not in deletable_tags(c):
        return False, f"出口 {old} 不存在或不可改名(direct 出口是模板锚点)"
    new = _tag(new.strip(), "", "")
    if not re.search(r"[A-Za-z0-9]", new):
        return False, "新名字无效: 用字母/数字/_/./-(不支持中文), 40 字内"
    if new == old:
        return False, "新旧名字相同, 未改动"
    if new in ("direct", "直连", "block", "dns-out", "jp"):
        return False, f"{new} 是保留字, 换个名字"
    if new in [o["tag"] for o in c["outbounds"]]:
        return False, f"名字 {new} 已被占用"
    def mod(cc):
        for o in cc["outbounds"]:
            if o.get("tag") == old:
                o["tag"] = new
            if o.get("type") == "urltest":
                o["outbounds"] = [new if m == old else m for m in o.get("outbounds", [])]
        for r in cc["route"]["rules"]:
            if r.get("outbound") == old:
                r["outbound"] = new
        if cc["route"].get("final") == old:
            cc["route"]["final"] = new
    ok, msg = apply_sb(mod)
    if not ok:
        return False, msg
    m = _rs_meta(); dirty = False
    for info in m.values():
        if info.get("outbound") == old:
            info["outbound"] = new; dirty = True
    if dirty:
        _save_rs_meta(m)
    return True, f"✅ 出口 <b>{old}</b> 已改名 <b>{new}</b>, 分流规则/故障组/默认出口里的引用已同步。"

def urltest_groups(c):
    return [o["tag"] for o in c["outbounds"] if o.get("type") == "urltest"]

# ── Telegram 独立 SOCKS5(tg-proxy 入口)的出口选择 ──
TG_INBOUND = "tg-proxy"

def _tg_exit(c):
    """tg-proxy 入口被钉到的出口; 返回 None 表示跟随默认出口(final)。"""
    for r in c["route"]["rules"]:
        if r.get("inbound") == [TG_INBOUND]:
            return r.get("outbound")
    return None

def set_tg_exit(tag):
    """钉 Telegram(tg-proxy)走某出口; tag 空 = 跟随默认出口(删掉专属规则)。"""
    c = load()
    if tag and tag not in exit_tags(c):
        return False, f"出口 {tag} 不存在"
    def mod(cc):
        cc["route"]["rules"] = [r for r in cc["route"]["rules"] if r.get("inbound") != [TG_INBOUND]]
        if tag:  # 放在 reject 之后、域名/规则集规则之前, 确保优先按入口判定
            idx = 1 if cc["route"]["rules"] and cc["route"]["rules"][0].get("action") == "reject" else 0
            cc["route"]["rules"].insert(idx, {"inbound": [TG_INBOUND], "outbound": tag})
    ok, msg = apply_sb(mod)
    return ok, (f"✅ Telegram 出口 → {tag or '默认出口'}" if ok else msg)

# ── 测域名: 输入域名 → 直连 or 哪个出口(命中哪条规则/规则集) ──
def _internal_probe_ip():
    """从 mosdns npn_clients 段取一个探测地址(末位 .250), 用作内网卡来源查 mosdns。"""
    try:
        m = re.search(r'ips:\s*\[\s*"([^"/]+)', open(MOSDNS_CONF).read())
        if m:
            o = m.group(1).split(".")
            if len(o) == 4:
                o[3] = "250"; return ".".join(o)
    except Exception:  # noqa: BLE001
        pass
    return ""

def _match_ruleset(name, d, sufs):
    p = os.path.join(RS_DIR, name + ".yaml")
    if not os.path.exists(p):
        return False
    try:
        lines = open(p).read().splitlines()
    except Exception:  # noqa: BLE001
        return False
    for line in lines:
        s = line.strip()
        if not s.startswith("- "):
            continue
        parts = [x.strip() for x in s[2:].split(",", 1)]
        if len(parts) != 2:
            continue
        typ, val = parts[0].upper(), parts[1]
        if typ == "DOMAIN" and d == val:
            return True
        if typ == "DOMAIN-SUFFIX" and (d == val or d.endswith("." + val)):
            return True
        if typ == "DOMAIN-KEYWORD" and val in d:
            return True
    return False

def _mihomo_route(d):
    sufs = [".".join(d.split(".")[i:]) for i in range(len(d.split(".")))]
    c = load()
    for r in c["route"]["rules"]:
        if "outbound" not in r:
            continue
        if d in r.get("domain", []) or any(d == s or d.endswith("." + s) for s in r.get("domain_suffix", [])):
            return r["outbound"], "显式域名规则"
        if any(k in d for k in r.get("domain_keyword", [])):
            return r["outbound"], "关键词规则"
        rs = r.get("rule_set")
        if rs and _match_ruleset(rs, d, sufs):
            label = _rs_meta().get(rs, {}).get("label") or rs
            return r["outbound"], f"规则集 {label}"
    return c["route"].get("final"), "默认(其余国际)"

def test_domain(domain):
    d = domain.strip().lstrip(".").lower().split("/")[0]
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", d):
        return "域名格式不对, 例: <code>netflix.com</code>"
    sip = _server_ip(); probe = _internal_probe_ip(); real = []
    if probe:
        sh(["ip", "addr", "add", probe + "/32", "dev", "lo"])
        try:
            out = sh(["dig", "+short", "+time=2", "+tries=1", "@127.0.0.1", "-b", probe, d, "A"]).stdout
            real = [x for x in out.split() if re.match(r"^\d+\.\d+\.\d+\.\d+$", x)]
        finally:
            sh(["ip", "addr", "del", probe + "/32", "dev", "lo"])
    head = f"🔎 <b>{d}</b>\n"
    if real and sip not in real:
        return head + f"→ 🏠 <b>国内直连</b>(mosdns 返回真实 IP {real[0]})"
    tag, why = _mihomo_route(d)
    res = head + f"→ 📤 出口 <b>{tag}</b>(命中: {why})"
    if not real:
        res += "\n<i>(没探到 DNS 结果, 直连/代理未实测; 以上为 mihomo 规则模拟)</i>"
    return res

# ── 自定义 DoT 域名 (certbot standalone 签证书 → 换 mosdns DoT 证书) ──
def set_dot_domain(domain):
    domain = domain.strip().lower().rstrip(".")
    if not re.match(r"^(?=.{1,253}$)([a-z0-9-]+\.)+[a-z]{2,}$", domain):
        return False, "域名格式不对"
    sip = _server_ip()
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(domain, None, socket.AF_INET)}
    except Exception:  # noqa: BLE001
        addrs = set()
    if sip not in addrs:
        return False, (f"{domain} 现在解析到 {addrs or '(解析不到)'}, 不是本机 {sip}。\n"
                       f"先在 DNS 商把它 A 记录指向 {sip}(Cloudflare 选「灰云 DNS only」), 生效后再试。")
    try:
        r = subprocess.run(
            ["certbot", "certonly", "--standalone", "-d", domain,
             "--non-interactive", "--agree-tos", "--register-unsafely-without-email", "--keep-until-expiring",
             "--pre-hook", "/usr/local/bin/proxy-gateway-open-cert-http.sh",
             "--post-hook", "/usr/local/bin/proxy-gateway-restore-firewall.sh"],
            capture_output=True, text=True, timeout=300)
    except Exception as e:  # noqa: BLE001
        return False, f"certbot 执行异常: {e}"
    if r.returncode != 0:
        return False, "证书签发失败:\n" + (r.stdout + r.stderr)[-500:]
    live = f"/etc/letsencrypt/live/{domain}"
    try:
        os.makedirs(CERT_DIR, exist_ok=True)
        shutil.copy(f"{live}/fullchain.pem", os.path.join(CERT_DIR, "fullchain.pem"))
        shutil.copy(f"{live}/privkey.pem", os.path.join(CERT_DIR, "privkey.pem"))
        os.chmod(os.path.join(CERT_DIR, "fullchain.pem"), 0o644)
        os.chmod(os.path.join(CERT_DIR, "privkey.pem"), 0o600)
        with open("/opt/pdg-bot/dot-domain", "w") as f:
            f.write(domain + "\n")
    except Exception as e:  # noqa: BLE001
        return False, f"证书已签发但部署失败: {e}"
    sh(["systemctl", "restart", "mosdns"])
    global _DOT_HOST
    _DOT_HOST = None  # 让 _dot_host() 重新读新证书 CN
    return True, (f"✅ DoT 域名已设为 <b>{domain}</b>\n"
                  f"• 手机私密 DNS 改成: <code>{domain}</code>\n"
                  "• 证书已签发, certbot.timer 自动续期\n"
                  "• iOS: 重新生成一次「📱 iOS 描述文件」即可(自动用新域名)")

# ── iOS 描述文件 ──
def _ios_profile(ssids=()):
    """ssids 非空时在 OnDemandRules 最前插一条「命中这些 SSID 的 Wi-Fi 强制直连(不启用 DoT)」;
    其余 Wi-Fi/蜂窝仍按模板里的 :81 探测判定。用 plistlib 插入, SSID 含 &<> 等也不会破 XML。"""
    if not os.path.exists(IOS_TMPL):
        raise FileNotFoundError("缺少模板 " + IOS_TMPL)
    t = open(IOS_TMPL).read()
    raw = (t.replace("__DOT_HOST__", _dot_host())
            .replace("__JP_IP__", _server_ip())
            .replace("__UUID1__", str(uuid.uuid4()).upper())
            .replace("__UUID2__", str(uuid.uuid4()).upper())).encode()
    if not ssids:
        return raw
    p = plistlib.loads(raw)
    p["PayloadContent"][0]["OnDemandRules"].insert(
        0, {"InterfaceTypeMatch": "WiFi", "SSIDMatch": list(ssids), "Action": "Disconnect"})
    return plistlib.dumps(p)

def _wloc_ca_der():
    if not os.path.exists(WLOC_CA):
        raise FileNotFoundError("共享 MITM CA 尚未生成")
    certificate = open(WLOC_CA, "rb").read()
    if certificate.startswith(b"-----BEGIN CERTIFICATE-----"):
        try:
            certificate = ssl.PEM_cert_to_DER_cert(certificate.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as e:
            raise ValueError("共享 MITM CA PEM 无法转换为 DER") from e
    if not certificate:
        raise ValueError("共享 MITM CA 为空")
    return certificate

def _wloc_ca_profile():
    certificate = _wloc_ca_der()
    cert_uuid = "A61C8705-EB50-5CE6-A6B0-DAEAD2E4D543"
    profile_uuid = "2F95DD00-4E22-5D30-A761-335C3F427D50"
    payload = {
        "PayloadContent": [{
            "PayloadCertificateFileName": "PrivDNS-WLOC-CA.cer",
            "PayloadContent": certificate,
            "PayloadDescription": "仅供自有 PrivDNS Gateway 共享 MITM 使用的根证书",
            "PayloadDisplayName": "PrivDNS Shared MITM CA",
            "PayloadIdentifier": "com.privdns-gateway.wloc.ca.certificate",
            "PayloadOrganization": "PrivDNS Gateway",
            "PayloadType": "com.apple.security.root",
            "PayloadUUID": cert_uuid,
            "PayloadVersion": 1,
        }],
        "PayloadDescription": "PrivDNS Gateway 服务端共享 MITM CA",
        "PayloadDisplayName": "PrivDNS Shared MITM CA",
        "PayloadIdentifier": "com.privdns-gateway.wloc.ca",
        "PayloadOrganization": "PrivDNS Gateway",
        "PayloadRemovalDisallowed": False,
        "PayloadScope": "System",
        "PayloadType": "Configuration",
        "PayloadUUID": profile_uuid,
        "PayloadVersion": 1,
    }
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=False)

# ── 配置备份 / 恢复 ──
BACKUP_FILES = [STATE, MIHOMO_CFG, MOSDNS_CONF, MOSDNS_DIRECT, MOSDNS_FORCE_PROXY, RS_META,
                WLOC_PRESETS, ADBLOCK_SOURCES]
RESTORE_MAP = {
    "etc/mihomo/state.json": STATE,
    "etc/mihomo/config.yaml": MIHOMO_CFG,
    "etc/mosdns/config.yaml": MOSDNS_CONF,
    "etc/mosdns/rules/custom_direct.txt": MOSDNS_DIRECT,
    "etc/mosdns/rules/force_proxy.txt": MOSDNS_FORCE_PROXY,
    "opt/pdg-bot/rulesets.json": RS_META,
    "etc/privdns-gateway/wloc-presets.json": WLOC_PRESETS,
    "etc/privdns-gateway/adblock-sources.json": ADBLOCK_SOURCES,
}

def backup_blob():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for p in BACKUP_FILES:
            if os.path.exists(p):
                tar.add(p, arcname=p.lstrip("/"))
        if os.path.isdir(RS_DIR):
            tar.add(RS_DIR, arcname=RS_DIR.lstrip("/"))
    return buf.getvalue()

def _machine_id(state_path, mos_path):
    """取一对 mihomo/mosdns 配置里的「本机身份」: (server_ip, internal_cidr, cert_dir)。"""
    ip = cidr = certdir = None
    try:
        c = json.load(open(state_path))
        for r in c.get("route", {}).get("rules", []):
            if r.get("action") == "reject":
                for x in r.get("ip_cidr", []):
                    if x.endswith("/32") and not x.startswith("127."):
                        ip = x.split("/")[0]
    except Exception:  # noqa: BLE001
        pass
    try:
        t = open(mos_path).read()
        m = re.search(r'ips:\s*\[\s*"([^"]+)"', t); cidr = m.group(1) if m else None
        m = re.search(r'cert:\s*"([^"]+)"', t); certdir = os.path.dirname(m.group(1)) if m else None
        if not ip:
            m = re.search(r'black_hole\s+([0-9.]+)', t); ip = m.group(1) if m else None
    except Exception:  # noqa: BLE001
        pass
    return ip, cidr, certdir

def restore_from(data):
    global STATE, MIHOMO_CFG, RS_DIR
    try:
        tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    except Exception:  # noqa: BLE001
        return False, "不是有效的 .tar.gz 备份文件"
    tmp = tempfile.mkdtemp(prefix="pdgrs")
    try:
        for m in tar.getmembers():
            if m.name.startswith("/") or ".." in m.name.split("/"):
                continue
            try:
                tar.extract(m, tmp)
            except Exception:  # noqa: BLE001
                pass
        newstate = os.path.join(tmp, "etc/mihomo/state.json")
        legacy_sb = os.path.join(tmp, "etc/sing-box/config.json")
        if not os.path.exists(newstate) and os.path.exists(legacy_sb):
            newstate = legacy_sb
        newmos = os.path.join(tmp, "etc/mosdns/config.yaml")
        if not os.path.exists(newstate):
            return False, "备份里没有 mihomo state 配置, 拒绝恢复"
        # 机器感知: 用「本机」身份覆盖备份带来的 server_ip / 内网卡段 / 证书路径。
        # 这样跨机导入(如把 .153 的备份导到 .200)只搬出口+分流+规则集, 不会把别人的 IP/证书路径搬来搞错位。
        cur = _machine_id(STATE, MOSDNS_CONF)
        bak = _machine_id(newstate, newmos)
        kept = []
        subs = [(bak[i], cur[i]) for i in range(3) if bak[i] and cur[i] and bak[i] != cur[i]]
        if subs:
            kept = [cur[i] for i in range(3) if bak[i] and cur[i] and bak[i] != cur[i]]
            for f in (newstate, newmos):
                if os.path.exists(f):
                    s = open(f).read()
                    for old, new in subs:
                        s = s.replace(old, new)
                    open(f, "w").write(s)
        # 先用临时 /etc/mihomo 目录生成并校验 mihomo 配置。
        cur_state, cur_cfg, cur_rs = STATE, MIHOMO_CFG, RS_DIR
        tmp_mihomo = os.path.join(tmp, "etc/mihomo")
        os.makedirs(tmp_mihomo, exist_ok=True)
        shutil.copy(newstate, os.path.join(tmp_mihomo, "state.json"))
        STATE = os.path.join(tmp_mihomo, "state.json")
        MIHOMO_CFG = os.path.join(tmp_mihomo, "config.yaml")
        RS_DIR = os.path.join(tmp_mihomo, "rs")
        try:
            _write(json.load(open(STATE)))
            chk = sh(["mihomo", "-t", "-d", tmp_mihomo])
        finally:
            STATE, MIHOMO_CFG, RS_DIR = cur_state, cur_cfg, cur_rs
        if chk.returncode != 0:
            return False, "备份的 mihomo 配置校验失败:\n" + (chk.stdout + chk.stderr)[-300:]
        ts = time.strftime("%Y%m%d-%H%M%S")
        shutil.copy(STATE, STATE + ".pre-restore-" + ts)
        restored = []
        for arc, dst in RESTORE_MAP.items():
            src = os.path.join(tmp, arc)
            if os.path.exists(src):
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy(src, dst); restored.append(os.path.basename(dst))
        src_rs = os.path.join(tmp, "etc/mihomo/rs")
        if os.path.isdir(src_rs):
            shutil.rmtree(RS_DIR, ignore_errors=True); shutil.copytree(src_rs, RS_DIR); restored.append("rs/")
        os.makedirs(os.path.dirname(STATE), exist_ok=True)
        shutil.copy(newstate, STATE)
        if "state.json" not in restored:
            restored.append("state.json")
        _write(load())
        r1 = sh(["systemctl", "restart", "mihomo"])
        if r1.returncode != 0:
            shutil.copy(STATE + ".pre-restore-" + ts, STATE); _write(load()); sh(["systemctl", "restart", "mihomo"])
            return False, "恢复后 mihomo 启动失败, 已回滚 mihomo"
        sh(["systemctl", "restart", "mosdns"])
        msg = "已恢复: " + ", ".join(restored) + "\n已重启 mihomo + mosdns"
        if subs:
            msg += "\n(跨机导入: 已保留本机身份 " + "、".join(kept) + ", 只搬了出口+分流+规则集)"
        return True, msg
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

# ── 文案 ──
_DOT_HOST = None

def _dot_host():
    global _DOT_HOST
    if _DOT_HOST is None:
        try:
            out = sh(["openssl", "x509", "-in", CERT, "-noout", "-subject"]).stdout
            m = re.search(r"CN\s*=\s*([A-Za-z0-9.*-]+)", out)
            _DOT_HOST = m.group(1) if m else "?"
        except Exception:  # noqa: BLE001
            _DOT_HOST = "?"
    return _DOT_HOST

def _server_ip():
    try:
        for r in load()["route"]["rules"]:
            if r.get("action") == "reject":
                for cidr in r.get("ip_cidr", []):
                    if not cidr.startswith("127."):
                        return cidr.split("/")[0]
    except Exception:  # noqa: BLE001
        pass
    return "?"

def _groups_desc(c):
    g = [o for o in c["outbounds"] if o.get("type") == "urltest"]
    return "\n".join(f"🔀 故障组 <b>{o['tag']}</b>: {' › '.join(o.get('outbounds', []))}" for o in g)

def status_text():
    _st = sh(["systemctl", "is-active", "mosdns", "mihomo", "pdg-bot"]).stdout.split()
    _states = dict(zip(["mosdns", "mihomo", "pdg-bot"], _st + ["?", "?", "?"]))
    def dot(s):
        return "🟢" if _states.get(s) == "active" else "🔴"
    c = load(); exits = exit_tags(c)
    g = _groups_desc(c)
    final = c["route"].get("final")
    nrules = sum(1 for r in c["route"]["rules"] if r.get("outbound"))
    split = "国内直连" + (f" / {nrules} 条分流规则" if nrules else "") + f" / 其余→{final}"
    return ("🖥 <b>PrivDNS Gateway</b>\n\n"
            f"{dot('mosdns')} mosdns（DNS 分流, 带缓存）\n"
            f"{dot('mihomo')} mihomo（TPROXY 流量出口）\n"
            f"{dot('pdg-bot')} pdg-bot（管理）\n\n"
            f"📡 DoT: <code>{_dot_host()}:853</code>（Android 私密DNS / iOS 描述文件）\n"
            f"🌐 IP: <code>{_server_ip()}</code>\n"
            f"📤 出口({len(exits)}): {', '.join(exits)}\n"
            + (g + "\n" if g else "")
            + f"🎯 默认出口(其余国际): <b>{final}</b>\n"
            f"📚 规则集: {len(_rs_meta())} 个\n"
            f"🌏 分流: {split}")

def exits_text():
    c = load(); lines = []
    for o in proxy_outbounds(c):
        lines.append(f'• <b>{o["tag"]}</b>  {o["type"]}  {o.get("server")}:{o.get("server_port")}')
    for o in c["outbounds"]:
        if o.get("type") == "direct":
            lines.append(f'• <b>{o["tag"]}</b>  direct（本机直出）')
        elif o.get("type") == "urltest":
            lines.append(f'• <b>{o["tag"]}</b>  故障组 → {" › ".join(o.get("outbounds", []))}')
    return "出口:\n" + ("\n".join(lines) or "(无)")

def rules_text():
    c = load(); lines = []; m = _rs_meta()
    for r in c["route"]["rules"]:
        if "outbound" not in r:
            continue
        if r.get("rule_set"):
            info = m.get(r["rule_set"], {})
            label = info.get("label") or r["rule_set"]
            lines.append(f'→ <b>{r["outbound"]}</b>: [规则集 {label} · {info.get("count","?")}条]')
        else:
            doms = r.get("domain_suffix", []) + r.get("domain", [])
            if doms:
                lines.append(f'→ <b>{r["outbound"]}</b>: ' + ", ".join(doms[:12]) + (" …" if len(doms) > 12 else ""))
    txt = "分流规则:\n" + ("\n".join(lines) or f"(无显式规则, 其余→{c['route'].get('final')})")
    d = _read_direct()
    if d:
        txt += "\n\n自定义直连: " + ", ".join(d[:20])
    return txt

def kb_pick(prefix, tags, back=BACK):
    rows = [[{"text": t, "callback_data": f"{prefix}:{t}"}] for t in tags]
    rows.extend(_back_rows(back))
    return {"inline_keyboard": rows}

def kb_pick_named(prefix, items, back=BACK):
    """items=[(value, 显示文字)]: 按钮显示文字, 回调用 value。"""
    rows = [[{"text": label, "callback_data": f"{prefix}:{value}"}] for value, label in items]
    rows.extend(_back_rows(back))
    return {"inline_keyboard": rows}

# ── 回调 (原地编辑) ──
def handle_cb(chat, mid, data, cb_id=None):
    # 对齐 5GPN-X: 同一消息上一项慢操作未完成时, 提示稍候, 不重复排队
    if is_busy(chat, mid) and data not in ("menu", "status") and not str(data).startswith("nav:"):
        if cb_id:
            answer_cb_async(cb_id, "正在处理上一项操作，请稍候…")
        return
    if data in ("menu", "status") or data.startswith("nav:"):
        state.pop(chat, None); del_sel.pop(chat, None)   # 返回/切页 = 放弃进行中的输入流程和勾选
    if data in ("menu", "status"):
        edit(chat, mid, status_text(), MENU); return
    if data.startswith("nav:"):
        title, kb = _nav(data[4:]); edit(chat, mid, title, kb); return
    if data == "wloc":
        state.pop(chat, None)
        title, kb = _wloc_page(); edit(chat, mid, title, kb); return
    if data in ("wloc_ca", "adblock_ca"):
        state.pop(chat, None)
        back = WLOC_BACK if data == "wloc_ca" else ADBLOCK_BACK
        edit(chat, mid, "正在准备共享 MITM CA…", back)
        def _wca():
            ok, msg = _wloc_ensure_ca()
            if not ok:
                edit(chat, mid, "❌ " + msg, back); return
            try:
                cert = _wloc_ca_der()
                fingerprint = hashlib.sha256(cert).hexdigest().upper()
                send_document(chat, "PrivDNS-WLOC-CA.mobileconfig", _wloc_ca_profile(),
                              "📜 PrivDNS 共享 MITM CA\n"
                              f"SHA-256: <code>{fingerprint}</code>\n\n"
                              "安装后还要到 设置→通用→关于本机→证书信任设置，"
                              "对 <b>mitmproxy</b> 开启完全信任。")
                edit(chat, mid, "✅ CA 描述文件已发送。安装后请对 mitmproxy 开启完全信任，"
                     "已安装过同一 CA 则无需重复安装。", back)
            except Exception as e:  # noqa: BLE001
                edit(chat, mid, f"❌ CA 描述文件生成失败: {e}", back)
        run_bg(_wca); return
    if data == "wloc_pick":
        state[chat] = "wloc_location"
        edit(chat, mid, "✍️ <b>输入目标经纬度</b>\n"
             "发送 WGS84 <code>纬度,经度</code>，例如 <code>22.303611,114.165</code>。\n"
             "不想把坐标发到 Telegram 时，请返回 WLOC 直接点服务器预置地点。\n"
             "首次设置会启动共享 MITM sidecar 并重载一次 DNS/代理；以后换坐标无需重启。/cancel 取消。",
             WLOC_BACK); return
    if data.startswith("wloc_use:"):
        preset = _wloc_preset(data.split(":", 1)[1])
        if not preset:
            edit(chat, mid, "这个预置已不存在，请重新打开 WLOC 菜单。", WLOC_BACK); return
        edit(chat, mid, f"正在应用预置地点 <b>{_esc(preset['name'])}</b>…", WLOC_BACK)
        def _wp(p=preset):
            ok, msg = set_wloc(p["latitude"], p["longitude"], p["accuracy"], p["name"])
            title, kb = _wloc_page()
            edit(chat, mid, (("" if ok else "❌ ") + msg + "\n\n" + title), kb)
        run_bg(_wp); return
    if data == "wloc_off":
        edit(chat, mid, "确认关闭定位改写并恢复 Apple 原始定位？\n"
             "只撤销两个 Apple 定位域名；共享 CA 和其它 MITM 功能不受影响。",
             {"inline_keyboard": [
                 [{"text": "确认关闭定位改写", "callback_data": "wloc_off_yes"}],
                 [{"text": "取消", "callback_data": "wloc"}]]}); return
    if data == "wloc_off_yes":
        edit(chat, mid, "正在安全撤销 WLOC…", WLOC_BACK)
        def _woff():
            ok, msg = disable_wloc()
            title, kb = _wloc_page()
            edit(chat, mid, (("" if ok else "❌ ") + msg + "\n\n" + title), kb)
        run_bg(_woff); return
    if data == "adblock":
        state.pop(chat, None)
        title, kb = _adblock_page(); edit(chat, mid, title, kb); return
    if data == "adblock_sources":
        state.pop(chat, None)
        title, kb = _adblock_sources_page(); edit(chat, mid, title, kb); return
    if data == "adblock_domain_sources":
        state.pop(chat, None)
        title, kb = _adblock_domain_sources_page(); edit(chat, mid, title, kb); return
    if data == "adsrc_add":
        state[chat] = "adblock_add_source"
        edit(chat, mid, "发送一个 HTTPS Kelee/Loon/Egern 插件 URL。\n"
             "添加前会校验声明式规则；远程 JavaScript 和 ProtoBuf 不会执行。/cancel 取消。",
             ADBLOCK_BACK); return
    if data == "adrej_add":
        state[chat] = "adblock_add_domain_source"
        edit(chat, mid, "发送一个 HTTPS 普通 REJECT 规则源 URL。\n"
             "支持 Surge/Clash .list、纯域名/domain-set、Clash payload YAML/JSON；"
             "添加前会自动识别并校验。二进制 .mrs/.srs 不导入。/cancel 取消。",
             ADBLOCK_BACK); return
    if data.startswith("adsrc_del:"):
        source_id = data.split(":", 1)[1]
        source = next((item for item in _adblock_module_sources()
                       if item["id"] == source_id), None)
        if not source:
            title, kb = _adblock_sources_page()
            edit(chat, mid, "插件不存在或已删除。\n\n" + title, kb); return
        edit(chat, mid, f"确认删除 MITM 插件 <b>{_esc(source['name'])}</b>？\n"
             "若去广告已开启，会立即重新编译并应用剩余插件。",
             {"inline_keyboard": [
                 [{"text": "确认删除", "callback_data": "adsrc_del_yes:" + source_id}],
                 [{"text": "取消", "callback_data": "adblock_sources"}]]}); return
    if data.startswith("adsrc_del_yes:"):
        source_id = data.split(":", 1)[1]
        edit(chat, mid, "正在删除并重新编译去广告规则…", ADBLOCK_BACK)
        def _adsrc_delete(sid=source_id):
            ok, msg = delete_adblock_plugin(sid)
            title, kb = _adblock_sources_page()
            edit(chat, mid, (msg if ok else ("❌ " + msg)) + "\n\n" + title, kb)
        run_bg(_adsrc_delete); return
    if data.startswith("adrej_del:"):
        source_id = data.split(":", 1)[1]
        source = next((item for item in _adblock_domain_sources()
                       if item["id"] == source_id), None)
        if not source:
            title, kb = _adblock_domain_sources_page()
            edit(chat, mid, "规则源不存在或已删除。\n\n" + title, kb); return
        edit(chat, mid, f"确认删除普通 REJECT 规则源 <b>{_esc(source['name'])}</b>？\n"
             f"URL: <code>{_esc(source['url'])}</code>\n"
             "若去广告已开启，会立即重新编译并应用剩余来源。",
             {"inline_keyboard": [
                 [{"text": "确认按 URL 删除", "callback_data": "adrej_del_yes:" + source_id}],
                 [{"text": "取消", "callback_data": "adblock_domain_sources"}]]}); return
    if data.startswith("adrej_del_yes:"):
        source_id = data.split(":", 1)[1]
        edit(chat, mid, "正在删除规则源并重新生成 MRS…", ADBLOCK_BACK)
        def _adrej_delete(sid=source_id):
            ok, msg = delete_adblock_domain_source(sid)
            title, kb = _adblock_domain_sources_page()
            edit(chat, mid, (msg if ok else ("❌ " + msg)) + "\n\n" + title, kb)
        run_bg(_adrej_delete); return
    if data in ("adblock_on", "adblock_refresh"):
        edit(chat, mid, "正在下载并编译普通 REJECT 与 MITM 规则…", ADBLOCK_BACK)
        def _adon():
            ok, msg = enable_adblock()
            title, kb = _adblock_page()
            edit(chat, mid, (("" if ok else "❌ ") + msg + "\n\n" + title), kb)
        run_bg(_adon); return
    if data == "adblock_off":
        edit(chat, mid, "确认关闭去广告？\nWLOC 和共享 CA 不受影响。",
             {"inline_keyboard": [
                 [{"text": "确认关闭去广告", "callback_data": "adblock_off_yes"}],
                 [{"text": "取消", "callback_data": "adblock"}]]}); return
    if data == "adblock_off_yes":
        edit(chat, mid, "正在撤销去广告域名和规则…", ADBLOCK_BACK)
        def _adoff():
            ok, msg = disable_adblock()
            title, kb = _adblock_page()
            edit(chat, mid, (("" if ok else "❌ ") + msg + "\n\n" + title), kb)
        run_bg(_adoff); return
    if data == "setdot":
        state[chat] = "set_dot"
        edit(chat, mid, "发你的自定义 DoT 域名(先把它的 A 记录指向本机, Cloudflare 用「灰云 DNS only」)。\n"
             f"本机 IP: <code>{_server_ip()}</code>\n例: <code>dot.example.com</code>\n"
             "之后自动签 Let's Encrypt 证书并切换(约 30 秒内代理短暂中断)。/cancel 取消。", BACK); return
    if data.startswith("dosetdot:"):
        domain = data[9:]
        edit(chat, mid, f"正在为 <code>{domain}</code> 校验 A 记录并签证书(约 30-60 秒, 代理短暂中断)…", BACK)
        def _do():
            ok, msg = set_dot_domain(domain)
            edit(chat, mid, (msg if ok else "❌ " + msg), MENU)
        run_bg(_do); return
    if data == "test":
        edit(chat, mid, "测试中…", BACK)
        edit_bg(chat, mid, test_exits, BACK); return
    if data == "doctor":
        edit(chat, mid, "🩺 自检中(几秒)…", BACK)
        edit_bg(chat, mid, doctor_text, BACK); return
    if data == "upd_check":
        edit(chat, mid, "🔄 检查更新中…", BACK)
        def _upd():
            has, txt = update_check()
            kb = ({"inline_keyboard": [[{"text": "✅ 确认更新", "callback_data": "upd_apply"}],
                                       [{"text": "⬅️ 返回主菜单", "callback_data": "menu"}]]} if has else BACK)
            edit(chat, mid, txt, kb)
        run_bg(_upd); return
    if data == "upd_apply":
        ok = start_update()
        edit(chat, mid, ("🚀 已开始后台更新, 约 30-60 秒后 bot 自动回来(期间可能短暂无响应)。\n"
                         "完成后点「🩺 自检」确认。" if ok
                         else "❌ 启动更新失败, 请在终端跑 sudo pdg update。"), BACK); return
    if data == "traffic":
        edit(chat, mid, traffic_text(), BACK); return
    if data == "exit_list":
        edit(chat, mid, exits_text(), EXIT_BACK); return
    if data == "rules":
        edit(chat, mid, rules_text(), RULE_BACK); return
    if data == "add_exit":
        state[chat] = "add_exit"
        edit(chat, mid, "发一条节点链接：<code>ss:// vmess:// trojan:// vless://(含 reality) hysteria2:// tuic:// anytls:// socks5:// http://</code>,或 Surge 的 <code>名字 = ss, …</code> 行\n/cancel 取消。", EXIT_BACK); return
    if data == "add_grp":
        state[chat] = "add_group"
        edit(chat, mid, "发「<b>组名 出口1 出口2 …</b>」建故障切换组(自动选最快/坏了自动切)。\n"
             f"可选成员: {', '.join(concrete_tags(load()))}\n例: <code>main hk tw us</code>\n"
             "建好后可在「🎯 设默认出口」或规则里选它。/cancel 取消。", EXIT_BACK); return
    if data == "add_rule":
        state[chat] = "add_rule"
        edit(chat, mid, f"发「<b>域名 出口</b>」，出口: {', '.join(exit_tags(load()))} 或 <b>direct</b>\n例: <code>netflix.com hk</code> / <code>x.cn direct</code>\n/cancel 取消。", RULE_BACK); return
    if data == "edit_rule":
        rs = editable_rules(load())
        if not rs:
            edit(chat, mid, "暂无可改的分流规则", RULE_BACK); return
        rows = [[{"text": lbl, "callback_data": f"er:{i}"}] for i, lbl in rs]
        rows.extend(_back_rows(RULE_BACK))
        edit(chat, mid, "选要改出口的规则:", {"inline_keyboard": rows}); return
    if data.startswith("er:"):
        idx = data[3:]
        rows = [[{"text": t, "callback_data": f"ero:{idx}:{t}"}] for t in exit_tags(load())]
        rows.extend(_back_rows(RULE_BACK))
        edit(chat, mid, "改到哪个出口:", {"inline_keyboard": rows}); return
    if data.startswith("ero:"):
        _, idx, target = data.split(":", 2)
        edit(chat, mid, "⏳ 正在改出口…", RULE_BACK)
        def _ero(i=int(idx), t=target):
            ok, msg = reassign_rule(i, t)
            edit(chat, mid, msg if ok else ("❌ " + msg), RULE_BACK)
        run_bg(_ero); return
    if data == "order_exit":
        state[chat] = "order_exit"
        cur = [o["tag"] for o in load()["outbounds"]]
        edit(chat, mid, "发新的出口顺序(空格分隔, 含全部出口)。\n"
             f"当前: <code>{' '.join(cur)}</code>\n例: <code>hk tw jp us auto</code>\n/cancel 取消。", EXIT_BACK); return
    if data == "edit_grp":
        gs = urltest_groups(load())
        if not gs:
            edit(chat, mid, "还没有故障组, 先用「🔀 新建故障组」建一个。", EXIT_BACK); return
        edit(chat, mid, "选要改的故障组:", kb_pick("egrp", gs, EXIT_BACK)); return
    if data.startswith("egrp:"):
        name = data[5:]; state[chat] = "edit_grp:" + name
        cur = next((o.get("outbounds", []) for o in load()["outbounds"]
                    if o.get("tag") == name and o.get("type") == "urltest"), [])
        edit(chat, mid, f"发 <b>{name}</b> 组的新成员(空格分隔, 按顺序, 至少2个)。\n"
             f"当前: <code>{' '.join(cur) or '空'}</code>\n可选: {', '.join(concrete_tags(load()))}\n"
             f"例: <code>hk tw us</code>\n/cancel 取消。", EXIT_BACK); return
    if data == "del_rule":
        del_sel[chat] = set()
        items, kb = del_rule_kb(chat)
        if not items:
            edit(chat, mid, "暂无可删的单域名规则(规则集请用「🗑 删规则集」)。", RULE_BACK); return
        edit(chat, mid, "勾选要删的域名(可多选), 选好点「✅ 确认删除」一次删:", kb); return
    if data.startswith("dtog:"):
        d = data[5:]; sel = del_sel.setdefault(chat, set())
        sel.discard(d) if d in sel else sel.add(d)
        _, kb = del_rule_kb(chat)
        edit(chat, mid, "勾选要删的域名(可多选), 选好点「✅ 确认删除」一次删:", kb); return
    if data == "ddel":
        doms = list(del_sel.get(chat, set()))
        if not doms:
            _, kb = del_rule_kb(chat)
            edit(chat, mid, "还没勾选域名。勾选后再点「✅ 确认删除」:", kb); return
        edit(chat, mid, f"⏳ 正在删除 {len(doms)} 个域名并重启 mihomo…", RULE_BACK)
        del_sel.pop(chat, None)
        def _dd(ds=list(doms)):
            ok, msg = del_rules_bulk(ds)
            edit(chat, mid, msg if ok else ("❌ " + msg), RULE_BACK)
        run_bg(_dd); return
    if data == "testdom":
        state[chat] = "test_dom"
        edit(chat, mid, "发个域名, 查它走哪个出口/规则(还是国内直连)。\n例: <code>netflix.com</code>\n/cancel 取消。", RULE_BACK); return
    if data == "add_rs":
        state[chat] = "add_rs"
        edit(chat, mid, "发「<b>规则集URL 出口 [名称]</b>」(后缀 .list / .txt / .srs)。\n"
             f"出口: {', '.join(exit_tags(load()))}\n名称可留空(之后用「✏️ 改规则集名」改)。\n"
             "例: <code>https://.../Binance.list tw 币安</code>\n/cancel 取消。", RULE_BACK); return
    if data == "del_rs":
        if not _rs_meta():
            edit(chat, mid, "没有已添加的规则集", RULE_BACK); return
        edit(chat, mid, "选择要删除的规则集：", kb_pick_named("delrs", _rs_items(), RULE_BACK)); return
    if data == "edit_rs":
        if not _rs_meta():
            edit(chat, mid, "没有已添加的规则集", RULE_BACK); return
        edit(chat, mid, "选择要改名的规则集：", kb_pick_named("ers", _rs_items(), RULE_BACK)); return
    if data.startswith("ers:"):
        name = data[4:]; state[chat] = "rs_label:" + name
        cur = _rs_meta().get(name, {}).get("label") or name
        edit(chat, mid, f"发规则集 <code>{name}</code> 的新名称(显示用, 如 <b>币安</b> / <b>OpenAI</b>)。\n"
             f"当前: {cur}\n发「-」清除自定义名。/cancel 取消。", RULE_BACK); return
    if data == "tgexit":
        c = load(); cur = _tg_exit(c)
        rows = [[{"text": ("✓ " if t == cur else "") + t, "callback_data": "tgx:" + t}] for t in exit_tags(c)]
        rows.append([{"text": ("✓ " if not cur else "") + "跟随默认出口", "callback_data": "tgx:"}])
        rows.append([{"text": "⬅️ 返回主菜单", "callback_data": "menu"}])
        edit(chat, mid, "✈️ Telegram(SOCKS5 :8445)走哪个出口?\n"
             f"当前: <b>{cur or '默认出口'}</b>\n手机里 Telegram→设置→数据和存储→代理 填 SOCKS5 <code>{_server_ip()}:8445</code>。",
             {"inline_keyboard": rows}); return
    if data.startswith("tgx:"):
        target = data[4:]
        edit(chat, mid, "⏳ 正在切换 Telegram 出口…", MENU)
        def _tgx(t=target):
            ok, msg = set_tg_exit(t)
            if ok:
                msg += ("\n\n在 Telegram → 设置 → 数据和存储 → 代理 → 加 <b>SOCKS5</b>:\n"
                        f"服务器 <code>{_server_ip()}</code>\n端口 <code>8445</code>\n(无需用户名/密码)")
            edit(chat, mid, msg if ok else ("❌ " + msg), MENU)
        run_bg(_tgx); return
    if data == "del_exit":
        tags = deletable_tags(load())
        edit(chat, mid, "选择要删除的出口/故障组：" if tags else "没有可删的出口",
             kb_pick("delx", tags, EXIT_BACK) if tags else EXIT_BACK); return
    if data == "ren_exit":
        tags = deletable_tags(load())
        edit(chat, mid, "选择要改名的出口/故障组：" if tags else "没有可改名的出口",
             kb_pick("renx", tags, EXIT_BACK) if tags else EXIT_BACK); return
    if data.startswith("renx:"):
        old = data[5:]; state[chat] = "rename_exit:" + old
        edit(chat, mid, f"发出口 <b>{old}</b> 的新名字(字母/数字/_/./-, 40 字内)。\n"
             "分流规则、故障组、默认出口里的引用会一并同步。/cancel 取消。", EXIT_BACK); return
    if data == "setfinal":
        edit(chat, mid, "「其余国际」默认走哪个出口/组：", kb_pick("fin", exit_tags(load()), EXIT_BACK)); return
    if data == "ios":
        state[chat] = "ios_ssid"
        edit(chat, mid, "📱 <b>生成 iOS 描述文件</b>\n"
             "Wi-Fi/蜂窝下是否启用私密 DNS 都由 <code>:81</code> 探测自动判定(网络能走到网关才启用)。\n"
             "若有想<b>强制直连</b>的 Wi-Fi(如公司网、探测误判的酒店网), 发它的名字(SSID, 多个则每行一个)再生成;"
             "不需要就点「直接生成」。/cancel 取消。",
             {"inline_keyboard": [[{"text": "⏭ 直接生成", "callback_data": "iosgen"}],
                                  [{"text": "⬅️ 返回客户端", "callback_data": "nav:client"}],
                                  [{"text": "🏠 主菜单", "callback_data": "menu"}]]}); return
    if data == "iosgen":
        state.pop(chat, None)
        edit(chat, mid, "正在生成 iOS 描述文件…", BACK)
        def _ios():
            try:
                send_document(chat, "PrivDNS-Gateway.mobileconfig", _ios_profile(),
                              f"📱 iOS/iPadOS 私密DNS 描述文件\nDoT: {_dot_host()}\n"
                              "装法: 存到「文件」App → 点开 → 设置→通用→「已下载描述文件」→ 安装。\n"
                              "Wi-Fi/蜂窝均靠服务器 :81 探测激活, 安装时已自动配好。")
                edit(chat, mid, "✅ 描述文件已发送(见上一条)。", MENU)
            except Exception as e:  # noqa: BLE001
                edit(chat, mid, f"生成失败: {e}", MENU)
        run_bg(_ios); return
    if data == "backup":
        edit(chat, mid, "正在打包配置…", OPS_BACK)
        def _bak():
            try:
                fn = "pdg-backup-" + time.strftime("%Y%m%d-%H%M") + ".tar.gz"
                send_document(chat, fn, backup_blob(),
                              "💾 配置备份(含 mihomo 出口密码, 请妥善保存)。\n恢复: 点「♻️ 恢复」后把此文件发回。")
                edit(chat, mid, "✅ 备份已发送(见上一条)。", MENU)
            except Exception as e:  # noqa: BLE001
                edit(chat, mid, f"备份失败: {e}", MENU)
        run_bg(_bak); return
    if data == "restore":
        state[chat] = "restore"
        edit(chat, mid, "把之前「💾 备份」得到的 <code>.tar.gz</code> 作为文件发给我即可恢复"
             "(先 mihomo 配置测试, 失败自动回滚)。\n/cancel 取消。", BACK); return
    if data == "dnsup":
        state[chat] = "set_dns"
        rem = _upstreams("remote"); loc = _upstreams("local")
        mode = "🔓 WDA 解锁" if _wda_on() else "🛬 落地出口"
        edit(chat, mid, "🌐 <b>mosdns DNS 上游</b>\n"
             f"国际(remote): <code>{', '.join(rem) or '?'}</code>\n"
             f"国内(local): <code>{', '.join(loc) or '?'}</code>\n\n"
             f"<b>流媒体/服务解锁</b>: 当前 <b>{mode}</b>\n"
             "• 🛬 落地出口: 解锁服务走各自落地(hk/tw)\n"
             "• 🔓 WDA: WDA 能解锁的整体走 WDA(jp 直出 + 解锁 DNS)\n"
             f"  ⚠️ 开 WDA 前先去解锁服务后台授权本机 IP <code>{_server_ip()}</code>(没授权点 🔓 会被拦下)\n\n"
             "改上游: 发「<b>remote 地址…</b>」或「<b>local 地址…</b>」(空格分隔多个)\n/cancel 取消。",
             {"inline_keyboard": [
                 [{"text": "🛬 解锁走落地出口", "callback_data": "wda:off"},
                 {"text": "🔓 解锁走 WDA", "callback_data": "wda:on"}],
                 [{"text": "⬅️ 返回运维", "callback_data": "nav:ops"}],
                 [{"text": "🏠 主菜单", "callback_data": "menu"}]]}); return
    if data in ("wda:on", "wda:off"):
        edit(chat, mid, "正在切换解锁模式…", DNS_BACK)
        on = data == "wda:on"
        def _wda(v=on):
            ok, msg = set_wda_mode(v)
            edit(chat, mid, msg if ok else ("❌ " + msg), DNS_BACK)
        run_bg(_wda); return
    if data == "tfo":
        on = _tfo_on(load())
        edit(chat, mid, f"🚀 <b>TCP Fast Open</b>\n当前: <b>{'开启' if on else '关闭'}</b>\n"
             "降低到落地的握手延迟; 需落地端也支持, 否则自动回落普通握手。",
             {"inline_keyboard": [[{"text": "开启", "callback_data": "tfo:on"}, {"text": "关闭", "callback_data": "tfo:off"}],
                                  [{"text": "⬅️ 返回运维", "callback_data": "nav:ops"}],
                                  [{"text": "🏠 主菜单", "callback_data": "menu"}]]}); return
    if data in ("tfo:on", "tfo:off"):
        on = data == "tfo:on"
        edit(chat, mid, "⏳ 正在切换 TFO…", OPS_BACK)
        def _tfo(v=on):
            ok, msg = set_tfo(v)
            edit(chat, mid, msg if ok else ("❌ " + msg), OPS_BACK)
        run_bg(_tfo); return
    if data == "restart":
        edit(chat, mid, "⏳ 正在重启 mihomo + mosdns…", OPS_BACK)
        def _rst():
            ok, msg = apply_sb(lambda c: None); sh(["systemctl", "restart", "mosdns"])
            edit(chat, mid, "✅ 已重启 mihomo + mosdns" if ok else msg, OPS_BACK)
        run_bg(_rst); return
    if data == "updgeo":
        edit(chat, mid, "正在更新 geosite + 分流规则集 + 去广告规则…", OPS_BACK)
        def _geo():
            r = sh(["/bin/bash", UPDATE_SCRIPT]); n = refresh_rulesets(); ad_ok, ad_msg = refresh_adblock()
            if r.returncode == 0 and ad_ok:
                msg = f"✅ geosite 已更新; 分流规则集刷新 {n} 个\n{ad_msg}"
            else:
                msg = (("geosite 更新失败:\n" + (r.stdout + r.stderr)[-300:])
                       if r.returncode != 0 else ("去广告刷新失败: " + ad_msg))
            edit(chat, mid, msg, OPS_BACK)
        run_bg(_geo); return
    if data.startswith("delx:"):
        tag = data[5:]
        edit(chat, mid, f"⏳ 正在删除 {tag}…", EXIT_BACK)
        def _delx(t=tag):
            def mod(c):
                c["outbounds"] = [o for o in c["outbounds"] if o.get("tag") != t]
                for o in c["outbounds"]:
                    if o.get("type") == "urltest":
                        o["outbounds"] = [m for m in o.get("outbounds", []) if m != t]
                c["outbounds"] = [o for o in c["outbounds"]
                                  if not (o.get("type") == "urltest" and not o.get("outbounds"))]
                live = {o["tag"] for o in c["outbounds"]}
                for r in c["route"]["rules"]:
                    if r.get("outbound") and r["outbound"] not in live:
                        r["outbound"] = c["route"].get("final", "hk")
                if c["route"].get("final") not in live:
                    c["route"]["final"] = next((x for x in exit_tags(c)), "direct")
            ok, msg = apply_sb(mod)
            edit(chat, mid, f"✅ 已删除 {t}" if ok else msg, EXIT_BACK)
        run_bg(_delx); return
    if data.startswith("fin:"):
        tag = data[4:]
        edit(chat, mid, f"⏳ 正在切换默认出口 → {tag}…", EXIT_BACK)
        def _fin(t=tag):
            ok, msg = apply_sb(lambda c: c["route"].__setitem__("final", t))
            edit(chat, mid, f"✅ 默认出口 → {t}" if ok else msg, EXIT_BACK)
        run_bg(_fin); return
    if data.startswith("delrs:"):
        edit(chat, mid, "⏳ 正在删除规则集…", RULE_BACK)
        def _drs(name=data[6:]):
            ok, msg = del_ruleset(name)
            edit(chat, mid, ("✅ " if ok else "") + msg, RULE_BACK)
        run_bg(_drs); return

# ── 文本 ──
def _start_wloc_set(chat, latitude, longitude, label=None):
    send_plain(chat, "⏳ 正在应用 WLOC 目标位置…")
    def _set():
        try:
            ok, msg = set_wloc(latitude, longitude, label=label)
        except Exception as e:  # noqa: BLE001
            ok, msg = False, str(e)
        title, kb = _wloc_page()
        send(chat, (("" if ok else "❌ ") + msg + "\n\n" + title), kb)
    run_bg(_set)

def handle_text(chat, text, msg_id=None):
    text = text.strip()
    if text == "/cancel":
        state.pop(chat, None); send_plain(chat, "已取消"); return
    if text in ("/start", "/menu", "/status"):
        state.pop(chat, None); send(chat, status_text()); return
    if text.startswith("/"):
        cmd = text.split()[0]
        if cmd == "/test":
            send_plain(chat, "测试中…"); send_bg(chat, test_exits); return
        if cmd == "/doctor":
            send_plain(chat, "🩺 自检中…"); send_bg(chat, doctor_text, BACK); return
        if cmd == "/traffic":
            send(chat, traffic_text(), BACK); return
        if cmd == "/exits":
            send(chat, exits_text(), BACK); return
        if cmd == "/rules":
            send(chat, rules_text(), BACK); return
        if cmd == "/addexit":
            state[chat] = "add_exit"; send(chat, "发节点链接：<code>ss:// vmess:// trojan:// vless:// hysteria2:// tuic:// anytls:// socks5:// http://</code>,或 Surge 的 <code>名字 = ss, …</code> 行。/cancel 取消。", BACK); return
        if cmd == "/group":
            state[chat] = "add_group"; send(chat, "发「<b>组名 出口1 出口2 …</b>」建故障切换组。/cancel 取消。", BACK); return
        if cmd == "/addrule":
            state[chat] = "add_rule"; send(chat, f"发「<b>域名 出口</b>」，出口: {', '.join(exit_tags(load()))} 或 <b>direct</b>。/cancel 取消。", BACK); return
        if cmd == "/delrule":
            state[chat] = "del_rule"; send(chat, "发要删除的域名。/cancel 取消。", BACK); return
        if cmd == "/addrs":
            state[chat] = "add_rs"; send(chat, "发「<b>规则集URL 出口</b>」（支持 .list / .srs）。/cancel 取消。", BACK); return
        if cmd == "/delexit":
            tags = deletable_tags(load())
            send(chat, "选择删除的出口/组：" if tags else "无可删出口", kb_pick("delx", tags) if tags else BACK); return
        if cmd == "/setfinal":
            send(chat, "默认出口：", kb_pick("fin", exit_tags(load()))); return
        if cmd == "/delrs":
            m = _rs_meta()
            send(chat, "选择删除的规则集：" if m else "无规则集", kb_pick("delrs", list(m.keys())) if m else BACK); return
        if cmd == "/wloc":
            state.pop(chat, None)
            title, kb = _wloc_page(); send(chat, title, kb); return
        if cmd == "/adblock":
            state.pop(chat, None)
            title, kb = _adblock_page(); send(chat, title, kb); return
        if cmd == "/ios":
            try:
                send_document(chat, "PrivDNS-Gateway.mobileconfig", _ios_profile(), "📱 iOS 私密DNS 描述文件"); send_plain(chat, "✅ 已发送")
            except Exception as e:  # noqa: BLE001
                send_plain(chat, f"生成失败: {e}")
            return
        if cmd == "/backup":
            send_document(chat, "pdg-backup-" + time.strftime("%Y%m%d-%H%M") + ".tar.gz", backup_blob(), "💾 配置备份"); return
        if cmd == "/restore":
            state[chat] = "restore"; send(chat, "把备份 .tar.gz 作为文件发来。/cancel 取消。", BACK); return
        if cmd == "/setdot":
            parts = text.split()
            if len(parts) >= 2:
                send_plain(chat, "正在校验+签证书(约 30-60 秒, 代理短暂中断)…")
                ok, msg = set_dot_domain(parts[1]); send_plain(chat, msg if ok else ("❌ " + msg)); return
            state[chat] = "set_dot"; send(chat, f"发自定义 DoT 域名(A 记录先指向本机 {_server_ip()})。/cancel 取消。", BACK); return
        if cmd == "/restart":
            ok, _ = apply_sb(lambda c: None); sh(["systemctl", "restart", "mosdns"]); send_plain(chat, "✅ 已重启" if ok else "重启失败"); return
        if cmd == "/update":
            send_plain(chat, "更新中…"); r = sh(["/bin/bash", UPDATE_SCRIPT]); n = refresh_rulesets()
            ad_ok, ad_msg = refresh_adblock()
            send_plain(chat, (f"✅ 完成，分流规则集刷新 {n} 个\n{ad_msg}"
                              if r.returncode == 0 and ad_ok else "更新失败: " + ad_msg)); return
        send_plain(chat, "未识别命令，发 /start 打开菜单"); return
    act = state.pop(chat, None) or ""   # 无待输入时为 "", 避免下面 act.startswith(...) 在 None 上崩
    if act == "wloc_location":
        try:
            lat, lon = _wloc_parse_coordinates(text)
        except ValueError as e:
            state[chat] = "wloc_location"
            send(chat, f"坐标无效: {e}\n请重试，格式为 <code>纬度,经度</code>。/cancel 取消。", WLOC_BACK)
            return
        _start_wloc_set(chat, lat, lon); return
    if act == "adblock_add_source":
        send_plain(chat, "正在校验并添加 MITM 插件…")
        def _add_adblock_source(url=text):
            ok, msg = add_adblock_plugin(url)
            title, kb = _adblock_sources_page()
            send(chat, (msg if ok else ("❌ " + msg)) + "\n\n" + title, kb)
        run_bg(_add_adblock_source); return
    if act == "adblock_add_domain_source":
        send_plain(chat, "正在下载、识别并添加普通 REJECT 规则源…")
        def _add_adblock_domain(url=text):
            ok, msg = add_adblock_domain_source(url)
            title, kb = _adblock_domain_sources_page()
            send(chat, (msg if ok else ("❌ " + msg)) + "\n\n" + title, kb)
        run_bg(_add_adblock_domain); return
    if act == "add_exit":
        # 对齐 5GPN-X: 立刻删含密码消息 + 后台解析写入, 主循环不堵
        link = text
        mid = msg_id
        text = ""  # 尽快丢掉本地副本引用(后台闭包另持 link)
        def _add(payload=link, message_id=mid):
            warn = ""
            try:
                deleted = delete_message(chat, message_id)
                if not deleted and message_id is not None:
                    warn = "\n\n⚠️ 未能自动删除含凭据的消息, 请手动删掉上一条节点链接。"
                ob = parse_link(payload)
                def mod(c):
                    c["outbounds"] = [o for o in c["outbounds"] if o.get("tag") != ob["tag"]]
                    c["outbounds"].append(ob)
                ok, msg = apply_sb(mod)
                if ok:
                    send_plain(chat, f"✅ 已添加出口 <b>{ob['tag']}</b> ({ob['type']} {ob['server']}:{ob['server_port']})" + warn)
                else:
                    send_plain(chat, msg + warn)
            except Exception as e:  # noqa: BLE001
                send_plain(chat, f"解析失败: {e}" + warn)
            finally:
                payload = ""  # noqa: F841
        send_plain(chat, "⏳ 正在后台解析并写入出口…")
        run_bg(_add); return
    if act == "add_group":
        p = text.split()
        if len(p) < 3:
            send_plain(chat, "格式: 组名 出口1 出口2 …(至少2个出口)"); return
        send_plain(chat, "⏳ 正在创建故障组…")
        run_bg(lambda: send_plain(chat, (lambda r: r[1] if r[0] else ("❌ " + r[1]))(add_group(p[0], p[1:])))); return
    if act == "order_exit":
        order = text.replace(",", " ").split()
        send_plain(chat, "⏳ 正在更新出口顺序…")
        run_bg(lambda: send_plain(chat, (lambda r: r[1] if r[0] else ("❌ " + r[1]))(reorder_exits(order)))); return
    if act.startswith("edit_grp:"):
        name = act.split(":", 1)[1]
        members = text.replace(",", " ").split()
        send_plain(chat, "⏳ 正在更新故障组…")
        run_bg(lambda: send_plain(chat, (lambda r: r[1] if r[0] else ("❌ " + r[1]))(add_group(name, members)))); return
    if act.startswith("rename_exit:"):
        old = act.split(":", 1)[1]
        new = text
        send_plain(chat, f"⏳ 正在重命名 <b>{old}</b>…")
        run_bg(lambda: send_plain(chat, (lambda r: r[1] if r[0] else ("❌ " + r[1]))(rename_exit(old, new)))); return
    if act == "add_rule":
        p = text.split()
        if len(p) != 2:
            send_plain(chat, "格式: 域名 出口"); return
        send_plain(chat, "⏳ 正在添加规则…")
        run_bg(lambda: send_plain(chat, (lambda r: ("✅ " if r[0] else "") + r[1])(add_rule(p[0], p[1])))); return
    if act == "del_rule":
        d = text
        send_plain(chat, "⏳ 正在删除…")
        run_bg(lambda: send_plain(chat, (lambda r: ("✅ " if r[0] else "") + r[1])(del_rule(d)))); return
    if act == "test_dom":
        d = text
        send_plain(chat, "⏳ 查询中…")
        run_bg(lambda: send_plain(chat, test_domain(d))); return
    if act == "add_rs":
        p = text.split()
        if len(p) < 2:
            send_plain(chat, "格式: 规则集URL 出口 [名称]"); return
        send_plain(chat, "正在下载规则集…")
        url, outb, label = p[0], p[1], " ".join(p[2:])
        run_bg(lambda: send_plain(chat, (lambda r: ("✅ " if r[0] else "") + r[1])(add_ruleset(url, outb, label)))); return
    if act.startswith("rs_label:"):
        name = act.split(":", 1)[1]
        lab = "" if text.strip() == "-" else text
        run_bg(lambda: send_plain(chat, (lambda r: r[1] if r[0] else ("❌ " + r[1]))(set_ruleset_label(name, lab)))); return
    if act == "ios_ssid":
        ssids = [] if text.strip() == "-" else [l.strip()[:32] for l in text.splitlines() if l.strip()][:8]
        def _ios_ssid(ss=ssids):
            try:
                send_document(chat, "PrivDNS-Gateway.mobileconfig", _ios_profile(ss),
                              f"📱 iOS/iPadOS 私密DNS 描述文件\nDoT: {_dot_host()}\n"
                              + (("强制直连 Wi-Fi: " + ", ".join(ss) + "\n") if ss else "")
                              + "装法: 存到「文件」App → 点开 → 设置→通用→「已下载描述文件」→ 安装。")
                send_plain(chat, "✅ 已生成" + (f", {len(ss)} 个 Wi-Fi 设为强制直连" if ss else ""))
            except Exception as e:  # noqa: BLE001
                send_plain(chat, f"生成失败: {e}")
        run_bg(_ios_ssid); return
    if act == "set_dns":
        p = text.split()
        if len(p) < 2:
            send_plain(chat, "格式: remote|local 地址1 [地址2 …]"); return
        kind, addrs = p[0].lower(), p[1:]
        send_plain(chat, "⏳ 正在改 DNS 上游…")
        run_bg(lambda: send_plain(chat, (lambda r: r[1] if r[0] else ("❌ " + r[1]))(set_mosdns_upstream(kind, addrs)))); return
    if act == "set_dot":
        send_plain(chat, "正在校验域名并签发证书(约 30-60 秒, 期间代理短暂中断)…")
        def _sd(d=text):
            ok, msg = set_dot_domain(d)
            send_plain(chat, msg if ok else ("❌ " + msg))
        run_bg(_sd); return
    if act == "restore":
        send_plain(chat, "请把备份 <code>.tar.gz</code> 作为「文件」发来, 而不是文字。/cancel 取消。"); state[chat] = "restore"; return
    # 裸发一个像域名的文本: 当作想设 DoT 域名, 给一键按钮 (省得先点菜单进状态)
    if re.match(r"^(?=.{1,253}$)([a-z0-9-]+\.)+[a-z]{2,}$", text.lower()):
        d = text.lower()
        send(chat, f"想把 <code>{d}</code> 设成 DoT 自定义域名吗?\n"
                   f"先确认它的 A 记录已指向本机 <code>{_server_ip()}</code>(Cloudflare 用灰云 DNS only)。",
             {"inline_keyboard": [[{"text": "🌐 是, 签证书并切换", "callback_data": "dosetdot:" + d}],
                                  [{"text": "取消", "callback_data": "menu"}]]})
        return
    send_plain(chat, "发 /start 打开菜单")

# ── Telegram 位置 / 地点 ──
def handle_location(chat, location):
    if state.get(chat) != "wloc_location":
        title, kb = _wloc_page()
        send(chat, "收到位置。若要用于 WLOC，请先点「发送位置 / 经纬度」。\n\n" + title, kb)
        return
    state.pop(chat, None)
    try:
        lat, lon, _ = _wloc_validate(location.get("latitude"), location.get("longitude"))
    except (AttributeError, ValueError) as e:
        state[chat] = "wloc_location"
        send(chat, f"位置无效: {e}\n请重新发送。/cancel 取消。", WLOC_BACK)
        return
    _start_wloc_set(chat, lat, lon)

# ── 文件 (配置恢复) ──
def handle_document(chat, doc):
    if state.get(chat) != "restore":
        send_plain(chat, "如要恢复配置: 先点菜单「♻️ 恢复」再发备份文件。"); return
    state.pop(chat, None)
    send_plain(chat, "正在校验并恢复…")
    def _restore(fid=doc["file_id"]):
        try:
            data = tg_download(fid)
            ok, msg = restore_from(data)
        except Exception as e:  # noqa: BLE001
            ok, msg = False, f"恢复失败: {e}"
        send_plain(chat, ("✅ " if ok else "❌ ") + msg)
    run_bg(_restore)

def main():
    if not TOKEN:
        print("PDG_BOT_TOKEN 未设置, 退出"); return
    post("deleteWebhook", {"drop_pending_updates": False})
    cmds = [
        {"command": "start", "description": "打开菜单 / 状态"},
        {"command": "wloc", "description": "iOS WLOC 虚拟定位"},
        {"command": "adblock", "description": "普通规则 + MITM 去广告"},
        {"command": "cancel", "description": "取消当前输入"}]
    post("setMyCommands", {"commands": cmds})
    post("setMyCommands", {"commands": cmds, "scope": {"type": "all_private_chats"}})
    print("pdg-bot v3.1 (5GPN-X async UX) started, allowed:", ALLOWED, flush=True)
    off = 0
    while True:
        r = post("getUpdates", {"offset": off, "timeout": 50})
        if not r.get("ok"):          # 网络/API 出错 → 退避, 别紧打循环
            time.sleep(3); continue
        for u in r.get("result", []):
            off = u["update_id"] + 1
            try:
                if "message" in u:
                    m = u["message"]
                    if m["from"]["id"] not in ALLOWED:
                        continue
                    location = m.get("location") or m.get("venue", {}).get("location")
                    if "text" in m:
                        handle_text(m["chat"]["id"], m["text"], m.get("message_id"))
                    elif location:
                        handle_location(m["chat"]["id"], location)
                    elif "document" in m:
                        handle_document(m["chat"]["id"], m["document"])
                elif "callback_query" in u:
                    q = u["callback_query"]
                    # 先停按钮转圈(专用池), 再跑 handle_cb; 慢操作内部 edit_bg/run_bg
                    if q["from"]["id"] not in ALLOWED:
                        answer_cb_async(q["id"], "⛔ 未授权", show_alert=True)
                        continue
                    chat_id = q["message"]["chat"]["id"]
                    mid = q["message"]["message_id"]
                    data = q.get("data") or ""
                    # 对齐 5GPN-X: 同气泡慢操作未完成时只提示, 不重复入队
                    if is_busy(chat_id, mid) and data not in ("menu", "status") and not data.startswith("nav:"):
                        answer_cb_async(q["id"], "正在处理上一项操作，请稍候…")
                        continue
                    answer_cb_async(q["id"])
                    handle_cb(chat_id, mid, data, q["id"])
            except Exception as e:  # noqa: BLE001
                print("handle err", e, flush=True)

if __name__ == "__main__":
    main()
