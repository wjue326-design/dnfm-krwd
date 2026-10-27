#!/bin/bash
export PATH=/var/jb/usr/bin:/var/jb/usr/sbin:/usr/bin:/bin:/usr/sbin:/sbin
echo "=== first app dir ==="
ls -d /var/containers/Bundle/Application/*/*.app 2>/dev/null | head -5
echo "=== plutil test ==="
first=$(ls -d /var/containers/Bundle/Application/*/*.app 2>/dev/null | head -1)
echo "first=$first"
plutil -p "$first/Info.plist" 2>&1 | grep -E 'CFBundleIdentifier|CFBundleName' | head -4
echo "=== all bundle ids ==="
for p in /var/containers/Bundle/Application/*/*.app; do
  id=$(plutil -p "$p/Info.plist" 2>/dev/null | grep CFBundleIdentifier | sed 's/.*=> "//; s/".*//')
  [ -n "$id" ] && echo "$id  $(basename "$p")"
done | sort -u
echo "=== start frida-server ==="
nohup /var/jb/usr/sbin/frida-server -D >/var/log/frida-server.log 2>&1 &
sleep 3
lsof -iTCP:27042 2>/dev/null | head -3
launchctl list 2>/dev/null | grep -i frida
echo "=== libkrw strings (symbols) ==="
strings /var/jb/usr/lib/libkrw.0.dylib | grep -E '^_?k(read|write|base|call|sym|alloc|free)$' | sort -u
strings /var/jb/usr/lib/libkrw/libkrw-relaxin.dylib | grep -E 'kread|kwrite|kbase|kcall|ksym' | sort -u | head -10
echo "=== done ==="
