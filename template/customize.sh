# shellcheck disable=SC2034
SKIPUNZIP=1

DEBUG=@DEBUG@
SONAME=@SONAME@
SUPPORTED_ABIS="@SUPPORTED_ABIS@"

if [ "$BOOTMODE" ] && [ "$KSU" ]; then
  ui_print "- Installing from KernelSU app"
  ui_print "- KernelSU version: $KSU_KERNEL_VER_CODE (kernel) + $KSU_VER_CODE (ksud)"
  if [ "$(which magisk)" ]; then
    ui_print "*********************************************************"
    ui_print "! Multiple root implementation is NOT supported!"
    ui_print "! Please uninstall Magisk before installing Zygisk Next"
    abort    "*********************************************************"
  fi
elif [ "$BOOTMODE" ] && [ "$MAGISK_VER_CODE" ]; then
  ui_print "- Installing from Magisk app"
else
  ui_print "*********************************************************"
  ui_print "! Install from recovery is not supported"
  ui_print "! Please install from KernelSU or Magisk app"
  abort    "*********************************************************"
fi

VERSION=$(grep_prop version "${TMPDIR}/module.prop")
ui_print "- Installing $SONAME $VERSION"

# check architecture
support=false
for abi in $SUPPORTED_ABIS
do
  if [ "$ARCH" == "$abi" ]; then
    support=true
  fi
done
if [ "$support" == "false" ]; then
  abort "! Unsupported platform: $ARCH"
else
  ui_print "- Device platform: $ARCH"
fi

ui_print "- Extracting verify.sh"
unzip -o "$ZIPFILE" 'verify.sh' -d "$TMPDIR" >&2
if [ ! -f "$TMPDIR/verify.sh" ]; then
  ui_print "*********************************************************"
  ui_print "! Unable to extract verify.sh!"
  ui_print "! This zip may be corrupted, please try downloading again"
  abort    "*********************************************************"
fi
. "$TMPDIR/verify.sh"
extract "$ZIPFILE" 'customize.sh'  "$TMPDIR/.vunzip"
extract "$ZIPFILE" 'verify.sh'     "$TMPDIR/.vunzip"
extract "$ZIPFILE" 'sepolicy.rule' "$TMPDIR"

ui_print "- Extracting module files"
extract "$ZIPFILE" 'module.prop'     "$MODPATH"
extract "$ZIPFILE" 'post-fs-data.sh' "$MODPATH"
extract "$ZIPFILE" 'service.sh'      "$MODPATH"
extract "$ZIPFILE" 'action.sh'       "$MODPATH"
extract "$ZIPFILE" 'uninstall.sh'    "$MODPATH"
mv "$TMPDIR/sepolicy.rule" "$MODPATH"

ui_print "- Extracting WebUI and CLI"
unzip -o "$ZIPFILE" 'webroot/*' -d "$MODPATH" >&2
unzip -o "$ZIPFILE" 'bin/*' -d "$MODPATH" >&2
# Runtime does not need the per-file hashes; do not serve them from webroot.
rm -f "$MODPATH"/webroot/*.sha256 "$MODPATH"/webroot/cgi-bin/*.sha256 "$MODPATH"/bin/*.sha256

HAS32BIT=false && ([ $(getprop ro.product.cpu.abilist32) ] || [ $(getprop ro.system.product.cpu.abilist32) ]) && HAS32BIT=true

mkdir "$MODPATH/zygisk"

if [ "$ARCH" = "x86" ] || [ "$ARCH" = "x64" ]; then
  if [ "$HAS32BIT" = true ]; then
    ui_print "- Extracting x86 libraries"
    extract "$ZIPFILE" "lib/x86/lib$SONAME.so" "$MODPATH/zygisk/" true
    mv "$MODPATH/zygisk/lib$SONAME.so" "$MODPATH/zygisk/x86.so"
  fi

  ui_print "- Extracting x64 libraries"
  extract "$ZIPFILE" "lib/x86_64/lib$SONAME.so" "$MODPATH/zygisk" true
  mv "$MODPATH/zygisk/lib$SONAME.so" "$MODPATH/zygisk/x86_64.so"
else
  if [ "$HAS32BIT" = true ]; then
    extract "$ZIPFILE" "lib/armeabi-v7a/lib$SONAME.so" "$MODPATH/zygisk" true
    mv "$MODPATH/zygisk/lib$SONAME.so" "$MODPATH/zygisk/armeabi-v7a.so"
  fi

  ui_print "- Extracting arm64 libraries"
  extract "$ZIPFILE" "lib/arm64-v8a/lib$SONAME.so" "$MODPATH/zygisk" true
  mv "$MODPATH/zygisk/lib$SONAME.so" "$MODPATH/zygisk/arm64-v8a.so"
fi

ui_print "- Initializing runtime config"
TMC_DATA_DIR=/data/adb/trustmycert
mkdir -p "$TMC_DATA_DIR"
if [ ! -f "$TMC_DATA_DIR/config.conf" ]; then
  cat >"$TMC_DATA_DIR/config.conf" <<'EOF'
# TrustMyCert runtime config (managed by tmc / WebUI).
# Only listed target apps are instrumented. Missing config = no targets.
# Add one target= line per authorized test app, then restart the app.
# Changes are read by the root companion when an app process starts.
enabled=1
bypass=0
verbose=0
match_subprocesses=0
# target=com.example.app
EOF
  ui_print "- Created $TMC_DATA_DIR/config.conf (no targets yet)"
else
  ui_print "- Preserved existing $TMC_DATA_DIR/config.conf"
fi
chmod 0755 "$TMC_DATA_DIR"
chmod 0644 "$TMC_DATA_DIR/config.conf"

ui_print "- Setting permissions"
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/action.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755
set_perm "$MODPATH/bin/tmc" 0 0 0755
set_perm "$MODPATH/webroot/cgi-bin/api" 0 0 0755
