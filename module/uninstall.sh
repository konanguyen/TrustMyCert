#!/system/bin/sh
# TrustMyCert uninstall hook.
#
# The target allowlist is deliberately preserved so a module update or
# reinstall does not silently re-enable instrumentation on every app. Delete
# /data/adb/trustmycert manually if you want a clean slate.

rm -f /data/adb/trustmycert/ui.token
echo "[TrustMyCert] uninstalled; runtime config preserved in /data/adb/trustmycert"
