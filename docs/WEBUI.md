# TrustMyCert — Runtime configuration and WebUI

TrustMyCert never hooks "everything". Target selection is runtime-only and
fail-closed: a process is instrumented only when its package is listed in

```
/data/adb/trustmycert/config.conf
```

A missing, unreadable, empty, or malformed config enables **no** targets.
`system_server` is always rejected and `preServerSpecialize` always opts out.
This is intentional: instrumentation in unrelated processes can trip game
anti-cheat, banking RASP, and integrity checks.

## How the config reaches an app process

`/data/adb` is root-only, so app processes cannot read it directly. During
`preAppSpecialize` the module connects to the Zygisk **root companion**,
requests opcode `C`, and receives the config bytes over the socket. The
companion:

- serves exactly one compile-time path (`/data/adb/trustmycert/config.conf`);
- never accepts a path from the client, so it cannot be used as an arbitrary
  root file read;
- caps the response at 64 KiB;
- is ABI-aware (Zygisk runs a 32-bit companion for 32-bit processes).

If the companion is unavailable or the IPC fails, the module logs a
`Hook installation failed: ... (fail-closed)` line and calls
`DLCLOSE_MODULE_LIBRARY`. Nothing is instrumented.

Config is read once per process start. **Restart (force-stop) the target app
after editing the config.**

## Format

Line based, `key=value`, `#` starts a comment. Later assignments win.

```ini
enabled=1
bypass=0
verbose=0
match_subprocesses=0

# One line per authorized test app.
target=com.example.myapp
target=com.example.myapp.beta
```

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `0` if missing | Master switch. `0` = no instrumentation anywhere. |
| `bypass` | `0` | TEST-ONLY: override failed native verification. Also requires a build with `kEnableBypass=1` **and** `kAllowRuntimeBypass=1`; otherwise it is logged and ignored. |
| `verbose` | `0` | Extra per-library / per-symbol diagnostics. |
| `match_subprocesses` | `0` | Also match `<target>:<suffix>` process names. Keep `0` for games: subprocess hooking is the easiest way to trip anti-cheat. |
| `target` | none | Package/process name (`nice_name`) to instrument. Max 64 entries, 255 chars each. Duplicates are collapsed. |

Booleans accept `0/1`, `true/false`, `yes/no`, `on/off`.

Invalid targets (spaces, `:`, `/`, empty, `system_server`) and unknown keys are
ignored and reported in the module log as `Runtime config: ...`.

### Why not JSON?

The reference module uses JSON (`/data/local/tmp/zyg.ssl/config.json`). JSON
parsing inside a Zygisk companion without a dependency is easy to get wrong,
and hand-edited JSON fails hard on a missing comma. A line-based format is
trivially parseable in C++ and in the shell CLI, and the UI never requires
users to edit it by hand. The native parser is covered by
`test/runtime_config_host_test.cpp`.

## WebUI

The UI manages the same file. It is available in two forms.

### KernelSU / APatch (primary)

The module ships `webroot/index.html`. Open the module in KernelSU Manager /
APatch and tap the WebUI entry. The page calls the `tmc` CLI through
`ksu.exec` as root.

Features:

- master enable switch;
- per-app target list with add/remove and an installed-apps autocomplete
  (`pm list packages -3`, third-party apps only);
- subprocess matching and verbose toggles;
- test-only bypass behind an explicit confirmation panel;
- diagnostics panel showing CLI output.

### Magisk (action button fallback)

Magisk has no module WebUI. Tapping the module's Action button runs
`action.sh`, which:

1. creates the config if missing;
2. generates a random token in `/data/adb/trustmycert/ui.token` (mode `0600`);
3. starts BusyBox `httpd` on `127.0.0.1:8083` rooted at `webroot/`;
4. opens `http://127.0.0.1:8083/index.html#<token>` in a browser.

The token is passed in the URL **fragment**, which browsers do not send to the
server, so a local port scan cannot discover it. The CGI
(`webroot/cgi-bin/api`) only accepts a strict command whitelist and never
invokes the CLI through an evaluated shell string. To stop the fallback
server:

```bash
adb shell su -c 'pkill -f "httpd -p 127.0.0.1:8083"'
```

or reboot. Local HTTP is inherently a smaller security boundary than the
root-manager WebView; use it only on test devices.

## CLI

`bin/tmc` is a POSIX shell script usable from `adb shell su`:

```bash
TMC=/data/adb/modules/trustmycert/bin/tmc

$TMC list                 # effective key=value config
$TMC add com.example.app  # add target (also sets enabled=1)
$TMC remove com.example.app
$TMC set verbose 1
$TMC set match_subprocesses 0
$TMC set bypass 0
$TMC apps                 # installed third-party packages
$TMC validate             # syntax check + target count
$TMC path                 # config path
```

Writes are atomic (temp file + `mv`). Comments are replaced with a canonical
header on the first write; semantics are preserved. Concurrent writers are not
locked — use one UI/CLI at a time.

For host testing, `TMC_CONFIG=/tmp/.../config.conf` overrides the path.

## Manual configuration

```bash
adb root
adb shell 'cat > /data/adb/trustmycert/config.conf' <<'EOF'
enabled=1
bypass=0
verbose=0
match_subprocesses=0
target=com.example.myapp
EOF
adb shell chmod 0644 /data/adb/trustmycert/config.conf
```

Then force-stop and relaunch the app:

```bash
adb shell am force-stop com.example.myapp
adb shell monkey -p com.example.myapp 1
adb logcat -s TrustMyCert
```

Expected:

```
[TrustMyCert] Runtime config: loaded ... enabled=1 targets=1 bypass=0 ...
[TrustMyCert] Target process selected: com.example.myapp
[TrustMyCert] Hook installation successful: java/lang/Runtime.nativeLoad/...
[TrustMyCert] Target process specialized: com.example.myapp
```

## Troubleshooting

| Symptom | Cause / action |
|---|---|
| `Target process skipped: ... (module disabled by runtime config)` | `enabled=0`. |
| `Target process skipped: ... (not in runtime allowlist)` | Add the exact package name; check for a `:` suffix. |
| `Hook installation failed: companion connection unavailable` | Zygisk implementation lacks companion support, or module not active. Use a Zygisk build with companion support. |
| `Runtime config: loaded 0 bytes` | Config file missing/empty. Reinstall or create it. |
| Config change has no effect | App process still running. Force-stop and relaunch. |
| Magisk UI: `UI token missing` | Open the page via the Action button, not by typing the URL without the `#token` fragment. |
| Magisk UI: 403 | Stale page from a previous token; run the Action button again and reload. |
| `bypass=1` but logs say build disallows it | Rebuild with both compile-time gates; see `docs/CONFIG.md`. |

## Security properties and limits

- Only `target=` packages are instrumented; default deny.
- Subprocess matching is opt-in and off by default.
- Bypass is off by default, requires two compile-time gates plus a runtime
  opt-in, and is failure-only (genuine successes pass through).
- No secrets are stored or displayed. The config contains package names and
  booleans only.
- The UI is intended for the device owner on an authorized test device. A
  malicious app with root, or with access to the root manager's WebView, is
  outside the threat model.
- Zygisk briefly maps the module library into every specialized process before
  target selection. Non-targets get `DLCLOSE_MODULE_LIBRARY`, so the module
  leaves no mapping or hook there, but Zygisk/root itself may still be
  detectable by hardened anti-cheat. The allowlist prevents *this module* from
  instrumenting unrelated apps; it is not a general root-hiding feature.
- If your root manager does not expose a module WebUI entry (older APatch or a
  non-KernelSU manager), use `bin/tmc` from a root shell or `adb shell su`.
  The CLI manages the same file.
