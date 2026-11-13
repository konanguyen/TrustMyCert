#!/bin/sh
# Host-side test runner for TrustMyCert (no Android device required).
#
# Covers: native test lib vectors, discovery parser, runtime config
# parser/matching/companion framing, shell syntax, the tmc/CGI config path,
# and the read-only module log tail.
#
# Usage: sh test/run_host_tests.sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${TMPDIR:-/tmp}/tmc-host-tests
mkdir -p "$OUT"
CXX=${CXX:-g++}

cd "$ROOT"

echo "== native test lib"
"$CXX" -std=c++17 -Wall -Wextra test/native_testlib/test_main.cpp \
    test/native_testlib/testlib.cpp -o "$OUT/tmc_test"
"$OUT/tmc_test" | tail -n 1

echo "== discovery host test"
"$CXX" -std=c++17 -Wall -Wextra -Itest/host_stubs -Inative \
    test/discovery_host_test.cpp native/discovery.cpp -o "$OUT/tmc_disc"
"$OUT/tmc_disc"

echo "== runtime config host test"
"$CXX" -std=c++17 -Wall -Wextra -Itest/host_stubs -Inative \
    test/runtime_config_host_test.cpp native/runtime_config.cpp -o "$OUT/tmc_runtime"
"$OUT/tmc_runtime"

echo "== shell syntax"
for f in module/customize.sh module/action.sh module/uninstall.sh \
    module/bin/tmc module/webroot/cgi-bin/api test/run_host_tests.sh; do
    sh -n "$f"
done

if command -v node >/dev/null 2>&1; then
    echo "== webui javascript syntax"
    node --check module/webroot/app.js
fi

echo "== tmc CLI"
CONF=$OUT/config.conf
rm -f "$CONF"
TMC_CONFIG=$CONF sh module/bin/tmc add com.example.game >/dev/null
TMC_CONFIG=$CONF sh module/bin/tmc add com.example.bank >/dev/null
TMC_CONFIG=$CONF sh module/bin/tmc set verbose 1 >/dev/null
TMC_CONFIG=$CONF sh module/bin/tmc remove com.example.bank >/dev/null
TMC_CONFIG=$CONF sh module/bin/tmc validate >/dev/null
COUNT=$(TMC_CONFIG=$CONF sh module/bin/tmc get targets)
[ "$COUNT" = "1" ] || { echo "unexpected target count: $COUNT"; exit 1; }

echo "== tmc logs"
cat > "$OUT/logcat" <<'EOF'
#!/bin/sh
printf 'I/TrustMyCert( 1): [TrustMyCert] info line\n'
printf 'W/TrustMyCert( 1): [TrustMyCert] warning line\n'
printf 'E/TrustMyCert( 1): [TrustMyCert] error line\n'
EOF
chmod +x "$OUT/logcat"
LOGS=$(TMC_LOGCAT=$OUT/logcat sh module/bin/tmc logs 2)
printf '%s' "$LOGS" | grep -q 'warning line' || { echo "log tail missing warning"; exit 1; }
printf '%s' "$LOGS" | grep -q 'error line' || { echo "log tail missing error"; exit 1; }

echo "== CGI"
printf 'secret\n' > "$OUT/ui.token"
printf '#!/bin/sh\nexec sh %s/module/bin/tmc "$@"\n' "$ROOT" > "$OUT/tmc_wrap"
chmod +x "$OUT/tmc_wrap"
RESP=$(printf 'list' | REQUEST_METHOD=POST QUERY_STRING='token=secret' \
    TMC_CONFIG=$CONF TMC_UI_TOKEN_FILE=$OUT/ui.token TMC_CGI_ERR_FILE=$OUT/cgi.err \
    TMC_BIN=$OUT/tmc_wrap sh module/webroot/cgi-bin/api)
printf '%s' "$RESP" | grep -q '"errno":0' || { echo "CGI failed: $RESP"; exit 1; }
printf '%s' "$RESP" | grep -q 'target=com.example.game' || { echo "CGI target missing"; exit 1; }

RESP=$(printf 'logs 2' | REQUEST_METHOD=POST QUERY_STRING='token=secret' \
    TMC_CONFIG=$CONF TMC_UI_TOKEN_FILE=$OUT/ui.token TMC_CGI_ERR_FILE=$OUT/cgi.err \
    TMC_BIN=$OUT/tmc_wrap TMC_LOGCAT=$OUT/logcat sh module/webroot/cgi-bin/api)
printf '%s' "$RESP" | grep -q 'error line' || { echo "CGI log tail missing: $RESP"; exit 1; }

STATUS=$(printf 'logs 999' | REQUEST_METHOD=POST QUERY_STRING='token=secret' \
    TMC_CONFIG=$CONF TMC_UI_TOKEN_FILE=$OUT/ui.token TMC_CGI_ERR_FILE=$OUT/cgi.err \
    TMC_BIN=$OUT/tmc_wrap sh module/webroot/cgi-bin/api)
printf '%s' "$STATUS" | grep -q '400 Bad Request' || { echo "CGI accepted bad log count"; exit 1; }

echo "ALL HOST TESTS PASSED"
