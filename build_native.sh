#!/usr/bin/env bash
set -u
export MSYS2_ARG_CONV_EXCL='*'

VS="C:/Program Files/Microsoft Visual Studio/18/Insiders/VC/Tools/MSVC/14.51.36231"
SDK="C:/Program Files (x86)/Windows Kits/10/10.0.26100.0"
WK="C:/Program Files (x86)/Windows Kits/10"

export PATH="/c/Program Files/Microsoft Visual Studio/18/Insiders/VC/Tools/MSVC/14.51.36231/bin/Hostx64/x64:/c/Program Files (x86)/Windows Kits/10/bin/10.0.26100.0/x64:$PATH"
export INCLUDE="$VS/include;$WK/Include/10.0.26100.0/ucrt;$WK/Include/10.0.26100.0/um;$WK/Include/10.0.26100.0/shared;$WK/Include/10.0.26100.0/winrt;$WK/Include/10.0.26100.0/cppwinrt"
export LIB="$VS/lib/x64;$WK/Lib/10.0.26100.0/um/x64;$WK/Lib/10.0.26100.0/ucrt/x64"

SRC_DIR="src"
OBJ="build/obj/Release"
OUT="build/Release/WindChecker.exe"
mkdir -p "$OBJ" "build/Release"

CFLAGS="-nologo -MT -O2 -EHsc -std:c++17 -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX -W3 -c"

RC=0
echo "== rc =="
rc.exe -nologo -fo "$OBJ/app.res" "$SRC_DIR/app.rc" || RC=1

echo "== compile =="
for f in "$SRC_DIR"/*.cpp; do
  name=$(basename "$f" .cpp)
  if cl.exe $CFLAGS -Fo"$OBJ/$name.obj" "$f"; then
    :
  else
    echo "COMPILE FAILED: $name"
    RC=1
  fi
done

echo "== link =="
if [ "$RC" -eq 0 ]; then
  link.exe -nologo -SUBSYSTEM:WINDOWS -MANIFEST:NO -OUT:"$OUT" \
    "$OBJ"/*.obj "$OBJ/app.res" \
    kernel32.lib user32.lib comctl32.lib iphlpapi.lib ws2_32.lib dnsapi.lib \
    advapi32.lib userenv.lib winhttp.lib ole32.lib shell32.lib gdi32.lib \
    shlwapi.lib uxtheme.lib psapi.lib comdlg32.lib oleaut32.lib windowscodecs.lib \
    setupapi.lib cfgmgr32.lib wtsapi32.lib netapi32.lib esent.lib vssapi.lib 2>&1 || RC=1
fi

echo "compile-warnings/errors summary:"
grep -c "error" build/obj/Release/*.obj >/dev/null 2>&1
echo "done (RC=$RC)"
exit $RC
