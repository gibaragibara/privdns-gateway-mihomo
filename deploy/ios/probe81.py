#!/usr/bin/env python3
"""PrivDNS Gateway — iOS OnDemand 探测端点。
监听 0.0.0.0:81, 任意 GET 返回 204。配合 nftables 只放行 172.22.0.0/16 → :81,
普通卡探不通(被 drop)、内网卡探得通(204) → iOS OnDemand 据此只在内网卡(蜂窝)激活 DoT, 实现双卡区分。
"""
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(204); self.send_header("Content-Length", "0"); self.end_headers()
    do_HEAD = do_GET
    def log_message(self, *a):  # 静音
        pass

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 81), H).serve_forever()
