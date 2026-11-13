# TrustMyCert — Debugging guide

## Log filtering

Primary (by tag):

```bash
adb logcat -s TrustMyCert
```

Marker search across all tags (literal `[TrustMyCert]`):

```bash
adb logcat | grep -F '[TrustMyCert]'
```

Clear + capture a clean run:

```bash
adb logcat -c
adb logcat -s TrustMyCert > trustmycert.log
```

## Expected log sequence (target app launch)

```
[TrustMyCert] Module initialized (Zygisk API 4)
[TrustMyCert] Runtime config: loaded N bytes, enabled=1 targets=1 bypass=0 verbose=0 subprocesses=0
[TrustMyCert] Target process selected: com.example.trustmycert.test
[TrustMyCert] Hook installation successful: java/lang/Runtime.nativeLoad/2 (or /3)
[TrustMyCert] Diagnostic result: 1 JNI hooks installed
[TrustMyCert] Target process specialized: com.example.trustmycert.test
[TrustMyCert] Diagnostic result: N mapped files enumerated
[TrustMyCert] TLS implementation identified: <impl> (<lib path>)
[TrustMyCert] Pinning mechanism: impl=...; chain-validation=...; ...
[TrustMyCert] Hook commit: registered=R committed=yes
[TrustMyCert] Hook installation successful: SSL_get_verify_result origs=...
[TrustMyCert] Hook installation successful: X509_verify_cert origs=...
[TrustMyCert] Hook installation successful: SSL_CTX_set_verify origs=...
```

Non-target process: only the module/config lines plus a skip line at debug
priority (`verbose=1` raises it to info; `system_server` is always info):

```
[TrustMyCert] Target process skipped: <name> (not in runtime allowlist)
```

Module disabled in the runtime config:

```
[TrustMyCert] Target process skipped: <name> (module disabled by runtime config)
```

Companion unavailable (fail-closed):

```
[TrustMyCert] Hook installation failed: companion connection unavailable (fail-closed)
```

## Failure cases

| Symptom | Meaning | Action |
|---|---|---|
| No logs at all for the app | Module not loaded (Zygisk off / module disabled / denylist) or wrong tag filter | Check Magisk/KernelSU module list, enable Zygisk, `adb logcat \| grep -F '[TrustMyCert]'` |
| `Hook installation failed: Runtime.nativeLoad not found` | Unknown `Runtime` shape on this release | Pull framework descriptor per `docs/RESEARCH.md` §7, add variant |
| `pltHookCommit returned false` | PLT commit error | Report device/ROM/ABI; module continues observe-only via discovery |
| `no known TLS symbols resolved` | Stripped/static/custom TLS, or app TLS that never touches native verify (e.g. Java-only path, out of scope) | Expected for some apps — use the controlled test app to confirm methodology, don't assume absence of pinning |
| `forwarding ambiguous ... using RTLD_DEFAULT` | Multiple TLS builds in one process | Interpret verify logs cautiously; see `docs/RESEARCH.md` §4 |
| `Hook installation failed: companion connection unavailable` | Zygisk implementation without companion support, or module not active | Use a Zygisk build implementing the companion API; without it the module stays fail-closed |
| `Runtime config: loaded 0 bytes` | Config file missing or empty | Reinstall, create it with `tmc add`, or use the WebUI |
| `Target process skipped ... module disabled` | `enabled=0` | `tmc set enabled 1` |
| `Runtime bypass requested but build disallows it` | `bypass=1` in config, build gates off | Expected for release builds; see `docs/CONFIG.md` |
| WebUI shows `UI token missing` | Magisk fallback opened without the `#token` fragment | Use the module Action button; see `docs/WEBUI.md` |
| `TEST-ONLY bypass compiled in` / `bypass is ACTIVE` on a build you ship | Bypass flags left on | Revert `kEnableBypass`/`kAllowRuntimeBypass`, rebuild |

## Never in logs (by design)

Private keys, auth tokens, cookies, full TLS payloads. Wrappers log results
and callback pointers only. If you see secret material in a log line, treat it
as a bug and file it.
