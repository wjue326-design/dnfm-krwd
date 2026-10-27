#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dnfm-kit —— DNFM（iOS）运行时数据采集与协议分析一体化工具
一个文件跑完：SSH 进越狱手机 -> Frida 隧道 -> 拉游戏 -> dump il2cpp -> 抓网络帧 -> 扫检测 -> 出报告

依赖：paramiko、frida（pip 已装）
用法：
    python dnfm_kit.py all          # 全套（dump + net + detect + report）
    python dnfm_kit.py dump         # 只 dump 类/字段/协议表
    python dnfm_kit.py net --sec 60 # 抓网络帧
    python dnfm_kit.py detect       # 扫检测特征
    python dnfm_kit.py report       # 用已有产物生成报告

配置在 CONFIG 里改（IP/密码/包名），其余自动发现。
"""
import argparse, json, os, re, socket, struct, sys, threading, time

CONFIG = {
    "host": "192.168.1.37",
    "user": "mobile",
    "password": "1234567890",
    "bundle": "com.tencent.cdnf",
    "frida_port": 27042,
    "out": os.path.join(os.path.dirname(os.path.abspath(__file__)), "out"),
}

# ------------------------------------------------------------------ SSH utils
def ssh_client():
    import paramiko
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(CONFIG["host"], 22, CONFIG["user"], CONFIG["password"], timeout=12,
              allow_agent=False, look_for_keys=False)
    return c

def sh(c, cmd, sudo=True, timeout=120):
    if sudo:
        cmd = "echo '%s' | sudo -S -p '' bash -c \"%s\"" % (CONFIG["password"], cmd.replace('"', '\\"'))
    i, o, e = c.exec_command(cmd, timeout=timeout)
    return o.read().decode("utf-8", "replace").strip()

def find_container(c, bundle):
    out = sh(c, "ls -d /var/mobile/Containers/Data/Application/*/Library/Preferences/%s.plist 2>/dev/null | head -1" % bundle)
    if not out:
        return None
    return out.rsplit("/Library/Preferences/", 1)[0]

# ------------------------------------------------------------------ frida tunnel
class Tunnel:
    def __init__(self, c, local_port=27999):
        self.c, self.local_port = c, local_port
        self.tr = c.get_transport()
        threading.Thread(target=self._serve, daemon=True).start()
        time.sleep(0.4)
        import frida
        self.dev = frida.get_device_manager().add_remote_device("127.0.0.1:%d" % local_port)

    def _serve(self):
        srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.local_port)); srv.listen(8)
        while True:
            cli, _ = srv.accept()
            try:
                ch = self.tr.open_channel("direct-tcpip", ("127.0.0.1", CONFIG["frida_port"]), ("127.0.0.1", 0))
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

def ensure_frida(c):
    out = sh(c, "launchctl list | grep -i -E 'frida' | head -3")
    if "frida" not in out:
        sh(c, "nohup /var/jb/usr/sbin/frida-server -l 127.0.0.1:%d >/var/log/frida-kit.log 2>&1 &" % CONFIG["frida_port"])
        time.sleep(3)

def ensure_app(t, pid):
    """spawn 或复用已有进程"""
    for p in t.dev.enumerate_processes():
        if p.name == "cdnf":
            return p.pid, False
    pid = t.dev.spawn([CONFIG["bundle"]])
    return pid, True

# ------------------------------------------------------------------ JS 代码块
JS_WAIT_UNITY = """
function E(n){ try{ var u=Process.findModuleByName("UnityFramework"); if(u && u.findExportByName){ var p=u.findExportByName(n); if(p) return p; } }catch(e){} try{ return Module.findGlobalExportByName(n); }catch(e){ return null; } }
function NF(n,r,a){ var p=E(n); if(!p) throw new Error("missing "+n); return new NativeFunction(p,r,a); }
function wait(function(){ if(!E("il2cpp_domain_get")) return setTimeout(arguments.callee,400); callback(); })
"""

JS_DUMP = r"""
var OUT_C="__CK__", OUT_F="__CF__", OUT_P="__CP__";
function E(n){ try{ var u=Process.findModuleByName("UnityFramework"); if(u && u.findExportByName){ var p=u.findExportByName(n); if(p) return p; } }catch(e){} try{ return Module.findGlobalExportByName(n); }catch(e){ return null; } }
function NF(n,r,a){ var p=E(n); if(!p) throw new Error("missing "+n); return new NativeFunction(p,r,a); }
function str(p){ try{ return p && !p.isNull()? p.readUtf8String() : ""; }catch(e){ return ""; } }
function start(){
  var dg=NF("il2cpp_domain_get","pointer",[]), dga=NF("il2cpp_domain_get_assemblies","pointer",["pointer","pointer"]);
  var agi=NF("il2cpp_assembly_get_image","pointer",["pointer"]), ign=NF("il2cpp_image_get_name","pointer",["pointer"]);
  var igc=NF("il2cpp_image_get_class_count","uint32",["pointer"]), igcl=NF("il2cpp_image_get_class","pointer",["pointer","uint32"]);
  var cgn=NF("il2cpp_class_get_name","pointer",["pointer"]), cns=NF("il2cpp_class_get_namespace","pointer",["pointer"]);
  var cgf=NF("il2cpp_class_get_fields","pointer",["pointer","pointer"]), fgn=NF("il2cpp_field_get_name","pointer",["pointer"]);
  var fgo=NF("il2cpp_field_get_offset","uint64",["pointer"]), fgt=NF("il2cpp_field_get_type","pointer",["pointer"]);
  var tgn=NF("il2cpp_type_get_name","pointer",["pointer"]);
  var fc=new File(OUT_C,"w"), ff=new File(OUT_F,"w"), fp=new File(OUT_P,"w");
  var stats={classes:0,fields:0,proto:0,errors:0};
  var filt=/Player|Monster|Report|Risk|Net|Dungeon|Item|Skill|Role|Attr|Boss|Sensor|Device|Anti|Cheat|Guild|Team|Unit|Buff|Drop|Shop|Bag|Task/i;
  var pf=/^(REQ_|RES_|NOTIFY_|CMD_|PB_|MSG_|S2C_|C2S_)|Report|Proto|Protocol|Packet/;
  var dom=dg(), n=Memory.alloc(8), asms=dga(dom,n), cnt=n.readU64().toNumber();
  for(var i=0;i<Math.min(cnt,256);i++){
    var img=null; try{ img=agi(asms.add(i*8).readPointer()); }catch(e){ continue; }
    if(!img) continue;
    var iname=str(ign(img)); var cc=0; try{ cc=igc(img); }catch(e){}
    if(cc>80000) cc=80000;
    for(var k=0;k<cc;k++){
      try{
        var klass=igcl(img,k); if(!klass) continue;
        var name=str(cgn(klass)), ns=str(cns(klass)); if(!name) name="cls"+k;
        fc.write(iname+"\t"+ns+"::"+name+"\n"); stats.classes++;
        var isP = pf.test(name)||pf.test(ns), isF = filt.test(name)||filt.test(ns);
        if(isF||isP){
          var it=Memory.alloc(8); it.writePointer(ptr(0)); var fld=null,g=0;
          try{ fld=cgf(klass,it); }catch(e){ fld=null; }
          var out = isP? fp : ff;
          while(fld && g++<4000){
            var fn=str(fgn(fld)), tn="", off=0;
            try{ off=fgo(fld); }catch(e){}
            try{ var tp=fgt(fld); tn=tp?str(tgn(tp)):""; }catch(e){}
            out.write("F\t"+iname+"\t"+ns+"::"+name+"\t"+fn+"\t"+off.toString()+"\t"+tn+"\n");
            if(isP) stats.proto++; else stats.fields++;
            try{ fld=cgf(klass,it); }catch(e){ break; }
          }
        }
      }catch(e){ stats.errors++; }
    }
  }
  try{fc.close();}catch(e){} try{ff.close();}catch(e){} try{fp.close();}catch(e){}
  send(stats);
}
var t0=Date.now();
(function boot(){
  var p=E("il2cpp_domain_get");
  if(p){
    try{ var f=new NativeFunction(p,"pointer",[]); var d=f(); if(d && !d.isNull()){ start(); return; } }catch(e){}
  }
  if(Date.now()-t0>200000) return send({error:"il2cpp not ready"});
  setTimeout(boot, 900);
})();
"""

JS_NET = r"""
var LOG="__LOG__", f=new File(LOG,"wb"), seen=0, count={};
function hex(p,len){ try{ return Array.from(new Uint8Array(p.readByteArray(len))).map(function(b){return b.toString(16).padStart(2,"0");}).join(""); }catch(e){ return ""; } }
function hook(name, dir, bufIdx, lenIdx){
  var a=Module.findGlobalExportByName(name); if(!a) return;
  Interceptor.attach(a,{
    onEnter:function(args){
      this.dir=dir; this.len=lenIdx>=0?args[lenIdx].toInt32():0; this.buf=bufIdx>=0?args[bufIdx]:null;
      if(dir===1 && this.len>0 && this.len<65536){ this.saved=Memory.alloc(this.len); this.buf.copy(this.saved); }
    },
    onLeave:function(ret){
      try{ var n=ret.toInt32(); if(n<=0) return; seen++; count[dir?"OUT":"IN"]=(count[dir?"OUT":"IN"]||0)+1; if(seen>4000) return;
        var src=this.dir?(this.saved||this.buf):this.buf; var ln=Math.min(n,8192);
        var hdr=new Uint8Array(5); hdr[0]=this.dir?1:0; hdr[1]=ln&255; hdr[2]=(ln>>8)&255; hdr[3]=(ln>>16)&255; hdr[4]=(ln>>24)&255;
        f.write(hdr.buffer); f.write(new Uint8Array(src.readByteArray(ln)));
      }catch(e){}
    }
  });
}
hook("send",1,1,2); hook("sendto",1,1,2); hook("recv",0,1,2); hook("recvfrom",0,1,2);
setTimeout(function(){ try{f.close();}catch(e){} send({done:true,count:count,seen:seen}); }, __SEC__*1000);
send({armed:true});
"""

# ------------------------------------------------------------------ 第一帧追踪
JS_TRACE = r"""
var LOG="__LOG__", f=new File(LOG,"w"), n=0, count={};
function hex(p,len){ try{ return Array.from(new Uint8Array(p.readByteArray(len))).map(function(b){return b.toString(16).padStart(2,"0");}).join(""); }catch(e){ return ""; } }
function cstr(p,len){ try{ var s=p.readUtf8String(len||128); return s?s.replace(/[^\x20-\x7e]/g,"."):""; }catch(e){ return ""; } }
function log(tag,name,detail){ if(n++>30000) return; count[tag]=(count[tag]||0)+1; try{ f.write(Date.now()+"\t"+tag+"\t"+name+"\t"+(detail||"")+"\n"); }catch(e){} }
function hookC(name, tag, spec){
  var a=Module.findGlobalExportByName(name); if(!a) return;
  try{
    Interceptor.attach(a,{ onEnter:function(args){
      try{
        var d=[];
        for(var i=0;i<spec.length;i++){
          var s=spec[i], v=args[i];
          if(s==="s") d.push("a"+i+"="+cstr(v,64));
          else if(s==="h") d.push("a"+i+"="+hex(v,32));
          else d.push("a"+i+"="+v);
        }
        log(tag,name,d.join(" "));
      }catch(e){}
    }});
  }catch(e){ log("ERR",name,String(e)); }
}
// 只记可疑的 getenv / sysctlbyname 名字，避免启动期刷爆
function envLike(name, tag, idx){
  var a=Module.findGlobalExportByName(name); if(!a) return;
  var re=/(DYLD|JAIL|jail|Cydia|frida|substrate|ellekit|tweak|inject|root|SIMULATOR|debug)/;
  try{ Interceptor.attach(a,{ onEnter:function(args){
    try{ var s=cstr(args[idx],96); if(s && re.test(s)) log(tag,name,"name="+s); }catch(e){}
  }}); }catch(e){}
}
envLike("getenv","ENV",0);
envLike("sysctlbyname","ENV",0);
hookC("dlopen","LOAD",["s","p"]);
hookC("dlsym","LOAD",["p","s"]);
hookC("ptrace","DBG",["p","p","p","p"]);
hookC("task_for_pid","DBG",["p","p","p"]);
hookC("csops","DBG",["p","p","p","p"]);
hookC("proc_pidinfo","DBG",["p","p","p","p","p"]);
function fsHook(name, tag){
  var a=Module.findGlobalExportByName(name); if(!a) return;
  var re=/(jb|Cydia|frida|substrate|ellekit|libhooker|\/bin\/|apt|dpkg|ssh|rootless|\/var\/jb|\/etc\/|libkrw|tweak)/i;
  try{
    Interceptor.attach(a,{ onEnter:function(args){
      try{ var s=cstr(args[0],160); if(s && re.test(s)) log(tag,name,"path="+s); }catch(e){}
    }});
  }catch(e){}
}
fsHook("stat","FS"); fsHook("lstat","FS"); fsHook("access","FS");
var openRe=/(jb|Cydia|frida|substrate|ellekit|libhooker|\/bin\/|apt|dpkg|ssh|rootless|\/var\/jb|\/etc\/|libkrw|tweak)/i;
(function(){ var a=Module.findGlobalExportByName("open"); if(!a) return;
  Interceptor.attach(a,{ onEnter:function(args){ try{ var s=cstr(args[0],160); if(s && openRe.test(s)) log("FS","open","path="+s); }catch(e){} } });
})();
(function(){ var a=Module.findGlobalExportByName("fopen"); if(!a) return;
  Interceptor.attach(a,{ onEnter:function(args){ try{ var s=cstr(args[0],160); if(s && openRe.test(s)) log("FS","fopen","path="+s); }catch(e){} } });
})();

hookC("send","NET",["p","h","p","p"]);
hookC("recv","NET",["p","p","p","p"]);
hookC("sendto","NET",["p","h","p","p","p","p"]);
hookC("recvfrom","NET",["p","p","p","p","p","p"]);
var done=false;
var timer=setInterval(function(){
  if(done) return;
  var m=Process.findModuleByName("CryptoLib"); if(!m) return;
  done=true;
  try{
    m.enumerateExports().forEach(function(e){
      if(!/TeaEncrypt|TeaDecrypt|oi_symmetry|CryptoTool/.test(e.name)) return;
      try{
        Interceptor.attach(e.address,{ onEnter:function(args){
          log("CRYPTO", e.name.slice(0,50), "a0="+args[0]+" hex0="+hex(args[0],32)+" s0="+cstr(args[0],48)+" a1="+args[1]+" a2="+args[2]+" hex2="+hex(args[2],32));
        }});
      }catch(err){}
    });
  }catch(e){}
},200);
setTimeout(function(){ try{f.close();}catch(e){} send({done:true,count:count,events:n}); }, __SEC__*1000);
send({armed:true});
"""

# ------------------------------------------------------------------ 采集动作
def do_dump(c, t, outdir):
    sh(c, "killall -9 cdnf 2>/dev/null; true")
    time.sleep(2)
    pid, fresh = ensure_app(t, None)
    print("[dump] app pid", pid, "fresh" if fresh else "existing")
    cont = find_container(c, CONFIG["bundle"])
    if not cont:
        print("[dump] 找不到容器"); return None
    paths = [cont + "/Documents/dnf_classes.tsv", cont + "/Documents/dnf_fields.tsv", cont + "/Documents/dnf_proto.tsv"]
    js = JS_DUMP.replace("__CK__", paths[0]).replace("__CF__", paths[1]).replace("__CP__", paths[2])
    if fresh:
        t.dev.resume(pid)
        time.sleep(45)          # 等 il2cpp 运行时初始化完成，再挂脚本
    s = t.dev.attach(pid)
    msgs = []
    sc = s.create_script(js)
    sc.on("message", lambda m, d: msgs.append(m.get("payload")))
    sc.load()
    t0 = time.time()
    while not msgs and time.time() - t0 < 420:
        time.sleep(1)
    print("[dump] result", msgs[:1])
    try: s.detach()
    except Exception: pass
    os.makedirs(outdir, exist_ok=True)
    sf = c.open_sftp()
    got = []
    for name, p in zip(("dnf_classes.tsv", "dnf_fields.tsv", "dnf_proto.tsv"), paths):
        try:
            st = sf.stat(p)
            sf.get(p, os.path.join(outdir, name))
            got.append((name, st.st_size))
        except Exception:
            pass
    sf.close()
    return got

def do_net(c, t, outdir, sec=60):
    sh(c, "killall -9 cdnf 2>/dev/null; true")   # 干净冷启动，保证有网络行为
    time.sleep(2)
    pid, fresh = ensure_app(t, None)
    cont = find_container(c, CONFIG["bundle"])
    logp = (cont or "/tmp") + "/Documents/dnf_net.bin"
    js = JS_NET.replace("__LOG__", logp).replace("__SEC__", str(sec))
    s = t.dev.attach(pid)
    msgs = []
    sc = s.create_script(js)
    sc.on("message", lambda m, d: msgs.append(m.get("payload")))
    sc.load()
    time.sleep(1)
    if fresh: t.dev.resume(pid)
    time.sleep(sec + 8)
    try: s.detach()
    except Exception: pass
    os.makedirs(outdir, exist_ok=True)
    local = os.path.join(outdir, "net.bin")
    sf = c.open_sftp()
    try:
        sf.get(logp, local); sf.close()
    except Exception as e:
        print("[net] pull fail", e); sf.close(); return None
    frames = parse_net(local, os.path.join(outdir, "frames.jsonl"))
    print("[net] frames", frames)
    return frames

def parse_net(path, outp):
    data = open(path, "rb").read()
    i, n, frames = 0, len(data), []
    while i + 5 <= n:
        d = data[i]; ln = int.from_bytes(data[i+1:i+5], "little"); i += 5
        if ln <= 0 or i + ln > n: break
        payload = data[i:i+ln]; i += ln
        if payload[:2] == b"\x22\x55" and len(payload) >= 11:
            total = int.from_bytes(payload[7:11], "little")
            frames.append({"dir": "out" if d else "in", "wire_len": ln,
                           "magic": "2255", "ver": payload[2:4].hex(),
                           "chan": payload[4:6].hex(), "declared_len": total,
                           "payload": payload.hex()[:200]})
    with open(outp, "w", encoding="utf-8") as fh:
        for f in frames:
            fh.write(json.dumps(f, ensure_ascii=False) + "\n")
    return len(frames)

def do_detect(c, outdir):
    app = sh(c, "ls -d /var/containers/Bundle/Application/*/cdnf.app | head -1")
    res = {}
    for kw in ("frida", "jailbreak", "Cydia", "substrate", "ptrace", "csops", "sysctl", "DYLD_INSERT"):
        out = sh(c, "grep -a -r -l -i '%s' %s/Frameworks 2>/dev/null | sed 's|.*/||' | sort -u | head -8" % (kw, app), timeout=300)
        res[kw] = [x for x in out.splitlines() if x]
    os.makedirs(outdir, exist_ok=True)
    json.dump(res, open(os.path.join(outdir, "detect.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("[detect]", {k: len(v) for k, v in res.items()})
    return res

def do_trace(c, t, outdir, sec=60):
    """从第一帧开始追踪：spawn 挂起 -> 装钩子 -> resume -> 记录 sec 秒"""
    sh(c, "killall -9 cdnf 2>/dev/null; true")
    time.sleep(2)
    pid = t.dev.spawn([CONFIG["bundle"]])
    cont = find_container(c, CONFIG["bundle"]) or "/tmp"
    logp = cont + "/Documents/dnf_trace.tsv"
    js = JS_TRACE.replace("__LOG__", logp).replace("__SEC__", str(sec))
    s = t.dev.attach(pid)
    msgs = []
    sc = s.create_script(js)
    sc.on("message", lambda m, d: msgs.append(m.get("payload")))
    sc.load()
    time.sleep(0.5)
    t.dev.resume(pid)          # 第一帧从这里开始，钩子已就位
    print("[trace] resumed pid", pid)
    time.sleep(sec + 12)
    try: s.detach()
    except Exception: pass
    os.makedirs(outdir, exist_ok=True)
    local = os.path.join(outdir, "trace.tsv")
    sf = c.open_sftp()
    try:
        sf.get(logp, local); sf.close()
    except Exception as e:
        print("[trace] pull fail", e); sf.close(); return None
    rows = sum(1 for _ in open(local, encoding="utf-8", errors="replace"))
    print("[trace] events", rows)
    return rows

def do_report(outdir, extra=None):
    os.makedirs(outdir, exist_ok=True)
    L = ["# DNFM（iOS）采集报告", ""]
    L.append("- 设备：iPhone 11 Pro / iOS 18.6.2 / arm64e")
    L.append("- 游戏：com.tencent.cdnf 130.5.8")
    L.append("- 时间：%s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    L.append("")
    for name, title in (("dnf_classes.tsv", "类表"), ("dnf_fields.tsv", "业务字段"), ("dnf_proto.tsv", "协议字段")):
        p = os.path.join(outdir, name)
        if os.path.exists(p):
            lines = sum(1 for _ in open(p, encoding="utf-8", errors="replace"))
            L.append("## %s" % title)
            L.append("")
            L.append("- 文件：%s（%d 行，%.1f KB）" % (name, lines, os.path.getsize(p)/1024.0))
            L.append("")
    fp = os.path.join(outdir, "frames.jsonl")
    if os.path.exists(fp):
        fr = [json.loads(x) for x in open(fp, encoding="utf-8") if x.strip()]
        L.append("## 网络帧")
        L.append("")
        L.append("- 帧数：%d（out %d / in %d）" % (len(fr), sum(1 for f in fr if f["dir"]=="out"), sum(1 for f in fr if f["dir"]=="in")))
        L.append("- 魔数：0x2255，版本位/通道号见 frames.jsonl")
        L.append("")
    dp = os.path.join(outdir, "detect.json")
    if os.path.exists(dp):
        d = json.load(open(dp, encoding="utf-8"))
        L.append("## 检测特征分布")
        L.append("")
        L.append("| 关键词 | 命中框架 |")
        L.append("|---|---|")
        for k, v in d.items():
            L.append("| %s | %s |" % (k, ", ".join(v[:6]) if v else "-"))
        L.append("")
    open(os.path.join(outdir, "REPORT.md"), "w", encoding="utf-8").write("\n".join(L) + "\n")
    print("[report] ->", os.path.join(outdir, "REPORT.md"))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", nargs="?", default="all", choices=["all", "dump", "net", "detect", "trace", "report"])
    ap.add_argument("--sec", type=int, default=60)
    a = ap.parse_args()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    outdir = os.path.join(CONFIG["out"], stamp)

    if a.mode == "report":
        base = CONFIG["out"]
        cands = sorted([d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d))], reverse=True) if os.path.isdir(base) else []
        for d in cands:
            p = os.path.join(base, d)
            if any(os.path.exists(os.path.join(p, f)) for f in ("dnf_classes.tsv", "frames.jsonl", "detect.json", "trace.tsv")):
                do_report(p); print("[done]", p); return
        print("[report] 没有任何采集产物可汇总"); return

    os.makedirs(outdir, exist_ok=True)
    c = ssh_client()
    print("[ssh] ok")
    if a.mode in ("all", "dump", "net", "trace"):
        ensure_frida(c)
        t = Tunnel(c)
        print("[frida] tunnel ok")
    else:
        t = None

    if a.mode in ("all", "detect"):
        do_detect(c, outdir)
    if a.mode in ("all", "dump"):
        do_dump(c, t, outdir)
    if a.mode in ("all", "trace"):
        do_trace(c, t, outdir, min(a.sec, 90))
    if a.mode in ("all", "net"):
        do_net(c, t, outdir, a.sec)
    do_report(outdir)
    c.close()
    print("[done]", outdir)

if __name__ == "__main__":
    main()
