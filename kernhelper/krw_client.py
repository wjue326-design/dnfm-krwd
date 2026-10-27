#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""krw_client.py —— 通过 SSH 隧道连手机上的 dnfm-krwd（127.0.0.1:27050）
用法：
    python krw_client.py ping
    python krw_client.py kbase
    python krw_client.py read 0xfffffff007004000 16
    python krw_client.py write 0xADDR deadbeef
"""
import json, socket, sys, time, threading
import paramiko

HOST = "192.168.1.37"
USER = "mobile"
PASSWORD = "1234567890"
DEV_PORT = 27050
LOCAL_PORT = 27051

class Tunnel:
    def __init__(self):
        c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(HOST, 22, USER, PASSWORD, timeout=10, allow_agent=False, look_for_keys=False)
        self.c = c; self.tr = c.get_transport()
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", LOCAL_PORT)); s.listen(4)
        self.srv = s
        threading.Thread(target=self._serve, daemon=True).start()
        time.sleep(0.3)
    def _serve(self):
        while True:
            cli, _ = self.srv.accept()
            try:
                ch = self.tr.open_channel("direct-tcpip", ("127.0.0.1", DEV_PORT), ("127.0.0.1", 0))
            except Exception:
                cli.close(); continue
            for a, b in ((cli, ch), (ch, cli)):
                threading.Thread(target=self._pump, args=(a, b), daemon=True).start()
    @staticmethod
    def _pump(a, b):
        try:
            while True:
                d = a.recv(65536)
                if not d: break
                b.sendall(d)
        except Exception:
            pass
        finally:
            for x in (a, b):
                try: x.close()
                except Exception: pass
    def request(self, obj):
        s = socket.create_connection(("127.0.0.1", LOCAL_PORT), timeout=8)
        s.sendall((json.dumps(obj) + "\n").encode())
        buf = b""
        s.settimeout(8)
        while b"\n" not in buf:
            d = s.recv(65536)
            if not d: break
            buf += d
        s.close()
        line = buf.split(b"\n")[0].decode("utf-8", "replace")
        return json.loads(line) if line else {"ok": False, "err": "empty"}

def main():
    if len(sys.argv) < 2:
        print(__doc__); return
    t = Tunnel()
    cmd = sys.argv[1]
    if cmd in ("kbase", "ping"):
        print(json.dumps(t.request({"cmd": cmd}), ensure_ascii=False))
    elif cmd == "read":
        n = int(sys.argv[3], 0) if len(sys.argv) > 3 else 32
        r = t.request({"cmd": "kread", "addr": sys.argv[2], "len": n})
        if r.get("ok"):
            h = r["hex"]
            print(" ".join(h[i:i+2] for i in range(0, len(h), 2)))
        else:
            print(r)
    elif cmd == "write":
        print(json.dumps(t.request({"cmd": "kwrite", "addr": sys.argv[2], "hex": sys.argv[3]}), ensure_ascii=False))
    else:
        print("unknown:", cmd)

if __name__ == "__main__":
    main()
