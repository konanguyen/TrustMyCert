#!/system/bin/sh
# TrustMyCert Magisk action button: serve the WebUI locally.
#
# KernelSU/APatch users do not need this path (the root manager shows
# webroot/index.html directly). Magisk has no module WebUI, so this starts a
# token-protected busybox httpd bound to 127.0.0.1 and opens it in a browser.

set -u

MODDIR=${0%/*}
DATA_DIR=/data/adb/trustmycert
CONF=$DATA_DIR/config.conf
PORT=8083
TOKEN_FILE=$DATA_DIR/ui.token

mkdir -p "$DATA_DIR" || {
    echo "[TrustMyCert] cannot create $DATA_DIR"
    exit 1
}

if [ ! -f "$CONF" ]; then
    cat >"$CONF" <<'EOF'
# TrustMyCert runtime config (managed by tmc / WebUI).
# Only listed target apps are instrumented. Missing config = no targets.
enabled=1
bypass=0
verbose=0
match_subprocesses=0
# target=com.example.app
EOF
    chmod 0644 "$CONF"
fi

TOKEN=$(head -c 32 /dev/urandom 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')
[ -n "$TOKEN" ] || {
    echo "[TrustMyCert] cannot generate UI token (no /dev/urandom or od)"
    exit 1
}
printf '%s\n' "$TOKEN" >"$TOKEN_FILE" || exit 1
chmod 0600 "$TOKEN_FILE"
rm -f "$MODDIR/webroot/token.js"

BB=""
for candidate in "$(command -v busybox 2>/dev/null)" \
    /data/adb/magisk/busybox /data/adb/ksu/bin/busybox /system/xbin/busybox /system/bin/busybox; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
        BB=$candidate
        break
    fi
done
[ -n "$BB" ] || {
    echo "[TrustMyCert] busybox not found; cannot start the local WebUI"
    exit 1
}

# BusyBox httpd daemonizes by default. If an earlier instance is already
# serving the same root, leave it running; the CGI re-reads ui.token on every
# request.
"$BB" httpd -p "127.0.0.1:$PORT" -h "$MODDIR/webroot" 2>/dev/null
sleep 1

# Verify only when the busybox build exposes wget; otherwise assume httpd is up.
if "$BB" --list 2>/dev/null | grep -qx "wget"; then
    if ! "$BB" wget -q -O /dev/null "http://127.0.0.1:$PORT/index.html" 2>/dev/null; then
        echo "[TrustMyCert] local WebUI did not start on 127.0.0.1:$PORT"
        echo "[TrustMyCert] port 8083 may be in use; close other local servers and retry"
        exit 1
    fi
fi

echo "[TrustMyCert] WebUI: http://127.0.0.1:$PORT/index.html#$TOKEN"
am start -a android.intent.action.VIEW -d "http://127.0.0.1:$PORT/index.html#$TOKEN" >/dev/null 2>&1 || {
    echo "[TrustMyCert] could not open a browser automatically"
    echo "[TrustMyCert] run the module action again or open the URL above manually"
}
