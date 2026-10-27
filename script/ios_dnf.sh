#!/bin/bash
export PATH=/var/jb/usr/bin:/var/jb/usr/sbin:/usr/bin:/bin:/usr/sbin:/sbin
p=$(ls -d /var/containers/Bundle/Application/*/cdnf.app | head -1)
echo "path=$p"
plutil -extract CFBundleIdentifier raw "$p/Info.plist" 2>&1
plutil -extract CFBundleExecutable raw "$p/Info.plist" 2>&1
plutil -extract CFBundleDisplayName raw "$p/Info.plist" 2>&1
echo "=== frameworks ==="
ls "$p" | head -20
ls "$p/Frameworks" 2>/dev/null | head -20
echo "=== running ==="
launchctl list 2>/dev/null | grep -i -E 'cdnf|dnf' | head
echo "=== size ==="
du -sh "$p" 2>/dev/null
