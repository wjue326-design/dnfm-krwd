#!/bin/bash
export PATH=/var/jb/usr/bin:/var/jb/usr/sbin:/usr/bin:/bin:/usr/sbin:/sbin
echo "=== dpkg core pkgs ==="
dpkg -l 2>/dev/null | grep -iE 'openssh|ellekit|krw|frida|ldid|substitute|libhooker' | awk '{print $2, $3}'
echo "=== apps bundle ids (dnf/tencent/tmgp) ==="
for p in /var/containers/Bundle/Application/*/*.app; do
  b=$(plutil -extract CFBundleIdentifier raw "$p/Info.plist" 2>/dev/null)
  case "$b" in *dnf*|*DNF*|*tencent*|*tmgp*|*Tencent*) echo "$b  $p";; esac
done
echo "=== total apps ==="
ls -d /var/containers/Bundle/Application/*/*.app 2>/dev/null | wc -l
echo "=== all bundle ids (first 40) ==="
for p in /var/containers/Bundle/Application/*/*.app; do plutil -extract CFBundleIdentifier raw "$p/Info.plist" 2>/dev/null; done | sort -u | head -40
echo "=== launchctl dnf/frida ==="
launchctl list 2>/dev/null | grep -iE 'dnf|tmgp|tencent|frida' | head -10
echo "=== frida ==="
ls -l /var/jb/usr/sbin/frida-server 2>/dev/null
lsof -iTCP:27042 2>/dev/null | head -3
echo "=== libkrw symbols ==="
nm -D /var/jb/usr/lib/libkrw.0.dylib 2>/dev/null | head -30
echo "=== relaxin libkrw strings ==="
strings /var/jb/usr/lib/libkrw/libkrw-relaxin.dylib 2>/dev/null | grep -iE '^(kread|kwrite|kbase|kcall|ksym|kalloc)|kernel_base|slide' | head -20
echo "=== jb type ==="
ls /var/jb/basebin 2>/dev/null | head -10
cat /var/jb/basebin/jbctl 2>/dev/null | head -1
echo "=== ps? ==="
ls /var/jb/usr/bin | grep -xE 'ps|top|procps' ; ls /usr/bin | grep -xE 'ps|top'
echo "=== done ==="
