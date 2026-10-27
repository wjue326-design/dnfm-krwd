#!/bin/bash
export PATH=/var/jb/usr/bin:/var/jb/usr/sbin:/usr/bin:/bin
echo "=== stop user service ==="
launchctl bootout user/501/re.frida.server 2>&1 | head -2
pkill -f frida-server 2>/dev/null; sleep 1
cp /tmp/com.xingshu.fridad.plist /var/jb/Library/LaunchDaemons/
chown root:wheel /var/jb/Library/LaunchDaemons/com.xingshu.fridad.plist
chmod 644 /var/jb/Library/LaunchDaemons/com.xingshu.fridad.plist
launchctl bootout system/com.xingshu.fridad 2>/dev/null
launchctl bootstrap system /var/jb/Library/LaunchDaemons/com.xingshu.fridad.plist 2>&1
sleep 2
launchctl print system/com.xingshu.fridad 2>&1 | grep -E 'state|program|pid' | head -5
echo "=== log ==="
tail -5 /var/log/fridad.log 2>/dev/null
echo "=== ps by frida? ==="
ls -l /var/run/ 2>/dev/null | head -3
echo "=== done ==="
