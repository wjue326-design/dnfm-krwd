#!/bin/bash
export PATH=/var/jb/usr/bin:/var/jb/usr/sbin:/usr/bin:/bin:/usr/sbin:/sbin
echo "=== app names ==="
ls -d /var/containers/Bundle/Application/*/*.app 2>/dev/null | sed 's|.*/||' | sort
echo "=== plutil locate/run ==="
ls -l /var/jb/usr/bin/plutil /usr/bin/plutil 2>&1
p=$(ls -d /var/containers/Bundle/Application/*/*.app | head -1)
/var/jb/usr/bin/plutil -p "$p/Info.plist" 2>&1 | head -5
echo "rc=$?"
echo "=== frida attempts ==="
cat /var/log/frida-server.log 2>/dev/null | head -10
ls /var/jb/Library/LaunchDaemons 2>/dev/null | grep -i frida
launchctl kickstart -k system/re.frida.server 2>&1
sleep 2
lsof -iTCP:27042 2>/dev/null | head -3
launchctl list 2>/dev/null | grep -i frida
echo "=== krw greps ==="
grep -a -o -E 'k(read|write|base|call|sym|alloc)' /var/jb/usr/lib/libkrw.0.dylib 2>/dev/null | sort -u | head
grep -a -o -E 'k(read|write|base|call|sym|alloc)' /var/jb/usr/lib/libkrw/libkrw-relaxin.dylib 2>/dev/null | sort -u | head
echo "=== done ==="
