#!/bin/bash
export PATH=/var/jb/usr/bin:/var/jb/usr/sbin:/usr/bin:/bin
echo "=== stop old ==="
launchctl bootout user/501/re.frida.server 2>&1 | head -2
pkill -f frida-server 2>/dev/null
sleep 1
echo "=== start lan-bound ==="
nohup /var/jb/usr/sbin/frida-server -l 0.0.0.0:27042 >/var/log/frida-lan.log 2>&1 &
sleep 3
cat /var/log/frida-lan.log | head -5
netstat -an 2>/dev/null | grep 27042 | head -3
echo "=== try uiopen? ==="
which uiopen; which open
echo "=== done ==="
