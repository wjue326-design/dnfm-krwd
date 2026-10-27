#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dnfm_mod.py —— DNFM（iOS）内核注入/内存修改器
  1) 内核侧：在 jbroot 感知的 root 进程里加载 libkrw，拿到内核读写（kbase/kread/kwrite RPC）
  2) 进程侧：Frida 注入游戏，暴露 il2cpp 反射 + 内存读写原语
  3) 修改器：按「类::字段」定位静态字段/偏移，读改写，做成可持续的修改链

用法：
    python dnfm_mod.py --test          # 自检：注入 + 类/字段/读内存
    python dnfm_mod.py --krw           # 只测内核读写（kbase）
    python dnfm_mod.py                 # 进交互式 REPL

REPL 命令：
    cls <关键字>            列出匹配的类
    fields <类全名>         列出字段（名/偏移/类型）
    rd <hexaddr> [n]        读内存
    wr <hexaddr> <hex>      写内存
    sv <类> <字段> <值>     读/写静态字段（读：只给类与字段）
    krw                    内核 kbase
    q                      退出
"""
import argparse, json, os, re, socket, struct, sys, threading, time

HOST = "192.168.1.37"
USER = "mobile"
PASSWORD = "1234567890"
BUNDLE = "com.tencent.cdnf"
FRIDA_PORT = 27042
TUNNEL_PORT = 27998

# ---------------------------------------------------------------- SSH
def ssh_client():
    import paramiko
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, 22, USER, PASSWORD, timeout=12, allow_agent=False, look_for_keys=False)
    return c

def sh(c, cmd, sudo=True, t=60):
    if sudo:
        cmd = "echo '%s' | sudo -S -p '' bash -c \"%s\"" % (PASSWORD, cmd.replace('"', '\\"'))
    i, o, e = c.exec_command(cmd, timeout=t)
    return o.read().decode("utf-8", "replace").strip()

# ---------------------------------------------------------------- tunnel
class Tunnel:
    def __init__(self, c, port=TUNNEL_PORT):
        import frida
        self.tr = c.get_transport(); self.port = port
        threading.Thread(target=self._serve, daemon=True).start()
        time.sleep(0.4)
        self.dev = frida.get_device_manager().add_remote_device("127.0.0.1:%d" % port)
    def _serve(self):
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", self.port)); s.listen(8)
        while True:
            cli, _ = s.accept()
            try:
                ch = self.tr.open_channel("direct-tcpip", ("127.0.0.1", FRIDA_PORT), ("127.0.0.1", 0))
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

# ---------------------------------------------------------------- 内核宿主
KRW_HOST_JS = r"""
var out = {};
function E(n){ try{ return Module.findGlobalExportByName(n); }catch(e){ return null; } }
function call(fn, ret, args, a){ var f=new NativeFunction(fn, ret, args); return f.apply(null, a); }
rpc.exports = {
  init: function(){
    try{
      var lib = null, tried = [];
      var paths = ["/var/tmp/libkrw3.dylib", "/var/tmp/libkrw2.dylib", "/private/var/tmp/libkrw.dylib", "/var/jb/usr/lib/libkrw.0.dylib", "/usr/lib/libkrw.0.dylib"];
      for (var pi=0; pi<paths.length; pi++) {
        try { lib = Module.load(paths[pi]); break; } catch(e){ tried.push(paths[pi]+": "+e); }
      }
      if (!lib) return { ok:false, err: tried.join(" | ") };
      var kb = E.call ? null : null;
      var kbaseFn = lib.findExportByName("kbase");
      var kreadFn = lib.findExportByName("kread");
      var kwriteFn = lib.findExportByName("kwrite");
      var base = new NativeFunction(kbaseFn, "pointer", [])();
      var buf = Memory.alloc(32);
      var rc = new NativeFunction(kreadFn, "int", ["pointer","pointer","uint64"])(base, buf, 32);
      return { ok: true, kbase: base.toString(), rc: rc, magic: buf.readU32().toString(16), uid: 0 };
    }catch(e){ return { ok:false, err: String(e) }; }
  },
  kread: function(addr, len){
    try{
      var lib = Process.findModuleByName("libkrw.0.dylib") || Process.findModuleByName("libkrw");
      var fn = lib.findExportByName("kread");
      var buf = Memory.alloc(len);
      var rc = new NativeFunction(fn, "int", ["pointer","pointer","uint64"])(ptr(addr), buf, len);
      return { rc: rc, hex: Array.from(new Uint8Array(buf.readByteArray(len))).map(function(b){return b.toString(16).padStart(2,"0");}).join("") };
    }catch(e){ return { err: String(e) }; }
  },
  kwrite: function(addr, hex){
    try{
      var lib = Process.findModuleByName("libkrw.0.dylib") || Process.findModuleByName("libkrw");
      var fn = lib.findExportByName("kwrite");
      var bytes = new Uint8Array(hex.length/2);
      for(var i=0;i<bytes.length;i++) bytes[i]=parseInt(hex.substr(i*2,2),16);
      var buf = Memory.alloc(bytes.length); buf.writeByteArray(bytes);
      var rc = new NativeFunction(fn, "int", ["pointer","pointer","uint64"])(ptr(addr), buf, bytes.length);
      return { rc: rc };
    }catch(e){ return { err: String(e) }; }
  }
};
"""

# ---------------------------------------------------------------- 游戏 agent
GAME_JS = r"""
var _i2 = {};
function E(n){ try{ var u=Process.findModuleByName("UnityFramework"); if(u && u.findExportByName){ var p=u.findExportByName(n); if(p) return p; } }catch(e){} try{ return Module.findGlobalExportByName(n); }catch(e){ return null; } }
function NF(n,r,a){ var p=E(n); if(!p) throw new Error("missing "+n); return new NativeFunction(p,r,a); }
function str(p){ try{ return p && !p.isNull()? p.readUtf8String() : ""; }catch(e){ return ""; } }
function boot(){
  try{
    _i2.dg=NF("il2cpp_domain_get","pointer",[]);
    _i2.dga=NF("il2cpp_domain_get_assemblies","pointer",["pointer","pointer"]);
    _i2.agi=NF("il2cpp_assembly_get_image","pointer",["pointer"]);
    _i2.ign=NF("il2cpp_image_get_name","pointer",["pointer"]);
    _i2.igc=NF("il2cpp_image_get_class_count","uint32",["pointer"]);
    _i2.igcl=NF("il2cpp_image_get_class","pointer",["pointer","uint32"]);
    _i2.cgn=NF("il2cpp_class_get_name","pointer",["pointer"]);
    _i2.cns=NF("il2cpp_class_get_namespace","pointer",["pointer"]);
    _i2.cgf=NF("il2cpp_class_get_fields","pointer",["pointer","pointer"]);
    _i2.fgn=NF("il2cpp_field_get_name","pointer",["pointer"]);
    _i2.fgo=NF("il2cpp_field_get_offset","uint64",["pointer"]);
    _i2.fgt=NF("il2cpp_field_get_type","pointer",["pointer"]);
    _i2.tgn=NF("il2cpp_type_get_name","pointer",["pointer"]);
    _i2.fsg=NF("il2cpp_field_static_get_value","void",["pointer","pointer"]);
    _i2.fss=NF("il2cpp_field_static_set_value","void",["pointer","pointer"]);
    _i2.cfn=NF("il2cpp_class_from_name","pointer",["pointer","pointer","pointer"]);
    _i2.d = _i2.dg();
    return true;
  }catch(e){ return String(e); }
}
function images(){
  var n=Memory.alloc(8), asms=_i2.dga(_i2.d, n), cnt=n.readU64().toNumber(), out=[];
  for(var i=0;i<Math.min(cnt,256);i++){ var img=_i2.agi(asms.add(i*8).readPointer()); if(img) out.push({name:str(_i2.ign(img)), ptr:img}); }
  return out;
}
function findAllImages(){
  var n=Memory.alloc(8), asms=_i2.dga(_i2.d, n), cnt=n.readU64().toNumber(), out=[];
  for(var i=0;i<Math.min(cnt,256);i++){ var img=_i2.agi(asms.add(i*8).readPointer()); if(img) out.push(img); }
  return out;
}
function findClass(name){
  var imgs=findAllImages();
  for(var i=0;i<imgs.length;i++){
    var cc=_i2.igc(imgs[i]);
    if(cc>100000) cc=100000;
    for(var k=0;k<cc;k++){
      var klass=_i2.igcl(imgs[i],k); if(!klass) continue;
      if(str(_i2.cgn(klass))===name) return klass;
    }
  }
  return null;
}
rpc.exports = {
  init: function(){ return boot(); },
  images: function(){ return images(); },
  findClass: function(name){ return String(findClass(name)); },
  fields: function(name){
    var klass=findClass(name); if(!klass) return [];
    var out=[], it=Memory.alloc(8); it.writePointer(ptr(0)); var fld;
    try{ fld=_i2.cgf(klass,it); }catch(e){ fld=null; }
    while(fld){
      var nm="?", off="0", ty="";
      try{ nm=str(_i2.fgn(fld)); }catch(e){}
      try{ off=_i2.fgo(fld).toString(); }catch(e){}
      try{ var tp=_i2.fgt(fld); if(tp) ty=str(_i2.tgn(tp)); }catch(e){}
      out.push({name:nm, off:off, type:ty});
      try{ fld=_i2.cgf(klass,it); }catch(e){ break; }
      if(out.length>2000) break;
    }
    return out;
  },
  staticGet: function(cls, field){
    var klass=findClass(cls); if(!klass) return {err:"no class"};
    var it=Memory.alloc(8); it.writePointer(ptr(0)); var fld;
    try{ fld=_i2.cgf(klass,it); }catch(e){ return {err:"fields"}; }
    while(fld){
      if(str(_i2.fgn(fld))===field){
        var buf=Memory.alloc(16); _i2.fsg(fld, buf);
        return {hex: Array.from(new Uint8Array(buf.readByteArray(16))).map(function(b){return b.toString(16).padStart(2,"0");}).join("")};
      }
      try{ fld=_i2.cgf(klass,it); }catch(e){ break; }
    }
    return {err:"no field"};
  },
  staticSet: function(cls, field, hex){
    var klass=findClass(cls); if(!klass) return {err:"no class"};
    var it=Memory.alloc(8); it.writePointer(ptr(0)); var fld;
    try{ fld=_i2.cgf(klass,it); }catch(e){ return {err:"fields"}; }
    while(fld){
      if(str(_i2.fgn(fld))===field){
        var b=new Uint8Array(hex.length/2); for(var i=0;i<b.length;i++) b[i]=parseInt(hex.substr(i*2,2),16);
        var buf=Memory.alloc(b.length); buf.writeByteArray(b);
        _i2.fss(fld, buf);
        return {ok:true};
      }
      try{ fld=_i2.cgf(klass,it); }catch(e){ break; }
    }
    return {err:"no field"};
  },
  selftest: function(){
    var out={};
    try{
      var u=Process.findModuleByName("UnityFramework");
      out.unity=u?u.base.toString():null;
      out.head=Array.from(new Uint8Array(u.base.readByteArray(16))).map(function(b){return b.toString(16).padStart(2,"0");}).join("");
    }catch(e){ out.readErr=String(e); }
    try{
      var p=Memory.alloc(16);
      p.writeByteArray([0xde,0xad,0xbe,0xef,1,2,3,4,5,6,7,8,9,10,11,12]);
      var back=Array.from(new Uint8Array(p.readByteArray(16))).map(function(b){return b.toString(16).padStart(2,"0");}).join("");
      out.writeRead=back; out.rwOk = back.indexOf("deadbeef")===0;
    }catch(e){ out.rwErr=String(e); }
    return out;
  },
  read: function(addr, len){ try{ return Array.from(new Uint8Array(ptr(addr).readByteArray(len))).map(function(b){return b.toString(16).padStart(2,"0");}).join(""); }catch(e){ return "ERR:"+e; } },
  write: function(addr, hex){ try{ var b=new Uint8Array(hex.length/2); for(var i=0;i<b.length;i++) b[i]=parseInt(hex.substr(i*2,2),16); ptr(addr).writeByteArray(b); return true; }catch(e){ return "ERR:"+e; } }
};
"""

def ensure_frida(c):
    if "frida" not in sh(c, "launchctl list | grep -i frida | head -3"):
        sh(c, "nohup /var/jb/usr/sbin/frida-server -l 127.0.0.1:%d >/var/log/frida-mod.log 2>&1 &" % FRIDA_PORT)
        time.sleep(3)

def find_game(t):
    for p in t.dev.enumerate_processes():
        if p.name == "cdnf":
            return p.pid
    pid = t.dev.spawn([BUNDLE]); t.dev.resume(pid); time.sleep(40)
    return pid

def attach_game(t, wait=True):
    pid = find_game(t)
    s = t.dev.attach(pid)
    sc = s.create_script(GAME_JS)
    sc.load()
    if wait:
        t0 = time.time()
        while time.time() - t0 < 200:
            try:
                if sc.exports_sync.init() is True:
                    break
            except Exception:
                pass
            time.sleep(1.5)
    return s, sc

def krw_probe(c, t):
    """在 jbroot 感知的 root 进程里加载 libkrw"""
    procs = list(t.dev.enumerate_processes())
    pref = [p.pid for p in procs if p.name in ("frida-server", "Frida")]
    pref += [p.pid for p in procs if p.name == "SpringBoard"]
    pref += [p.pid for p in procs if p.name in ("sshd", "jailbreakd")]
    if not pref:
        return {"ok": False, "err": "no jbroot host", "procs": [p.name for p in procs if "frida" in p.name.lower()]}
    pid = pref[0]
    s = t.dev.attach(pid)
    sc = s.create_script(KRW_HOST_JS); sc.load()
    r = sc.exports_sync.init()
    s.detach()
    return r

def fmt(b):
    return " ".join(b[i:i+2] for i in range(0, len(b), 2))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--test", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--krw", action="store_true")
    a = ap.parse_args()

    c = ssh_client(); print("[ssh] ok")
    ensure_frida(c)
    t = Tunnel(c); print("[frida] ok")

    if a.krw:
        print("[krw]", json.dumps(krw_probe(c, t), ensure_ascii=False)); return

    s, sc = attach_game(t); print("[game] attached")
    if a.selftest:
        print(json.dumps(sc.exports_sync.selftest(), ensure_ascii=False))
        s.detach(); c.close(); return
    if a.test:
        imgs = sc.exports_sync.images()
        print("[test] images", len(imgs))
        print("[test] find REQ_LOGIN ->", sc.exports_sync.findClass("REQ_LOGIN"))
        print("[test] fields ->", json.dumps(sc.exports_sync.fields("REQ_LOGIN")[:6], ensure_ascii=False))
        print("[test] krw ->", json.dumps(krw_probe(c, t), ensure_ascii=False))
        s.detach(); c.close(); return

    print("REPL: cls/fields/sv/rd/wr/krw/q")
    while True:
        try:
            line = input("dnfm> ").strip()
        except EOFError:
            break
        if not line: continue
        cmd, *rest = line.split()
        try:
            if cmd == "q": break
            elif cmd == "cls":
                kw = rest[0] if rest else ""
                imgs = sc.exports_sync.images()
                print("[i] %d images: %s" % (len(imgs), ", ".join(i["name"] for i in imgs[:10])))
            elif cmd == "fields":
                print(json.dumps(sc.exports_sync.fields(rest[0]), ensure_ascii=False, indent=1)[:4000])
            elif cmd == "sv":
                if len(rest) == 2: print(sc.exports_sync.staticGet(rest[0], rest[1]))
                else: print(sc.exports_sync.staticSet(rest[0], rest[1], rest[2]))
            elif cmd == "rd":
                n = int(rest[1], 0) if len(rest) > 1 else 32
                print(sc.exports_sync.read(rest[0], n))
            elif cmd == "wr":
                print(sc.exports_sync.write(rest[0], rest[1]))
            elif cmd == "krw":
                print(json.dumps(krw_probe(c, t), ensure_ascii=False))
            else:
                print("unknown")
        except Exception as e:
            print("[x]", e)
    s.detach(); c.close()

if __name__ == "__main__":
    main()
