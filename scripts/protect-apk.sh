#!/usr/bin/env bash
#
# protect-apk.sh — Proteksi APK generik berbasis dex2c (https://github.com/codehasan/dex2c)
#
# Script ini generik: bisa memproteksi APK apa saja, bukan cuma satu aplikasi.
# Kelas/method yang diprotect ditentukan lewat INPUT_INCLUDE / INPUT_EXCLUDE
# (atau otomatis: seluruh package utama aplikasi).
#
# Mode pemakaian:
#   protect-apk.sh prepare   - deteksi package name & generate filter.txt
#   protect-apk.sh setup     - clone dex2c, patch, install deps, tulis konfigurasi
#   protect-apk.sh protect   - jalankan dex2c (dengan retry) + zipalign + verifikasi
#   protect-apk.sh cleanup   - hapus APK input dari repo git (opsional)
#
# Input via environment (diisi dari workflow_dispatch inputs oleh GitHub Action):
#   INPUT_APK               path APK di repo (wajib)
#   INPUT_PACKAGE           package name, kosong = auto-deteksi via aapt
#   INPUT_INCLUDE           daftar include, satu per baris (kosong = semua class di package)
#   INPUT_EXCLUDE           daftar exclude, satu per baris (diawali ! = blacklist)
#   INPUT_LIB_NAME          nama native library, kosong = otomatis dari package
#   INPUT_CUSTOM_LOADER     kelas loader dex2c (default: miku.moe.app.DccApplication,
#                           bawaan dex2c: amimo.dcc.DccApplication)
#   INPUT_OBFUSCATE         true/false — obfuscate string constants
#   INPUT_DYNAMIC_REGISTER  true/false — pakai RegisterNatives
#   INPUT_MAX_ATTEMPTS      maksimal percobaan dex2c (default 5)
#   INPUT_CLEANUP           true/false — hapus APK dari repo setelah selesai
#   INPUT_ARCH              arm64 / armv7 / both — target ABI native (default: both)
#   CLEANUP_REF             branch untuk push cleanup (default: main)
#
# Format INPUT_INCLUDE / INPUT_EXCLUDE (satu per baris, boleh campur):
#   com.example.app                  -> semua class di package  => com/example/app/.*;.*
#   com.example.app.*                -> sama seperti di atas
#   com.example.app.MainActivity     -> satu class              => com/example/app/MainActivity;.*
#   com.example.app.Util.encrypt     -> satu method             => com/example/app/Util;encrypt\(.*
#   !com.example.app.BuildConfig     -> blacklist               => !com/example/app/BuildConfig;.*
#   com/foo/.*;.*                    -> aturan dex2c mentah (diteruskan apa adanya)
#
# Progress: script mencetak baris "[PROGRESS NN%] <tahap>" ke stdout.
# Bot Telegram mem-parsing log GitHub Actions untuk menampilkan progres real-time.
#
set -euo pipefail

MODE="${1:-protect}"

INPUT_APK="${INPUT_APK:-}"
INPUT_PACKAGE="${INPUT_PACKAGE:-}"
INPUT_INCLUDE="${INPUT_INCLUDE:-}"
INPUT_EXCLUDE="${INPUT_EXCLUDE:-}"
INPUT_LIB_NAME="${INPUT_LIB_NAME:-}"
INPUT_OBFUSCATE="${INPUT_OBFUSCATE:-false}"
INPUT_DYNAMIC_REGISTER="${INPUT_DYNAMIC_REGISTER:-false}"
INPUT_MAX_ATTEMPTS="${INPUT_MAX_ATTEMPTS:-5}"
INPUT_CLEANUP="${INPUT_CLEANUP:-true}"
INPUT_ARCH="${INPUT_ARCH:-both}"
INPUT_CUSTOM_LOADER="${INPUT_CUSTOM_LOADER:-miku.moe.app.DccApplication}"
CLEANUP_REF="${CLEANUP_REF:-main}"

WORK_DIR="work"
OUTPUT_DIR="output"
DEX2C_DIR="tools/dex2c"
STATE_DIR="$WORK_DIR/state"
FINAL_APK="$OUTPUT_DIR/app-protected-unsigned.apk"
EXCLUDE_FILE="$WORK_DIR/dex2c-method-excludes.txt"

APKTOOL_VERSION="2.12.1"
APKTOOL_FALLBACK_VERSION="2.11.1"
NDK_VERSION="25.2.9519653"

# ---------------------------------------------------------------- helpers ---
log()      { printf '[protect-apk] %s\n' "$*"; }
progress() { printf '[PROGRESS %s%%] %s\n' "$1" "$2"; }
die()      { printf '[protect-apk] FATAL: %s\n' "$*" >&2; exit 1; }

first_char() { # $1 = string -> huruf pertama
  local s="$1"
  printf '%s' "${s%"${s#?}"}"
}

# ------------------------------------------------- konversi aturan user ---
# Mengubah satu baris input user menjadi aturan filter dex2c.
# Mencetak aturan ke stdout, return 1 jika baris kosong/komentar.
to_rule() {
  local line="$1" neg=""
  line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  case "$line" in
    ''|\#*) return 1 ;;
  esac
  case "$line" in
    '!'*)
      neg='!'
      line="$(printf '%s' "${line#!}" | sed -e 's/^[[:space:]]*//')"
      ;;
  esac
  # Aturan mentah dex2c (mengandung / atau ;) diteruskan apa adanya.
  case "$line" in
    *[/\;]*) printf '%s%s\n' "$neg" "$line"; return 0 ;;
  esac

  local core="$line"
  case "$core" in
    *'.*') core="${core%.\*}" ;;  # "com.a.*" -> "com.a"
  esac
  local last="${core##*.}"        # segmen terakhir
  local rest="${core%.*}"         # sisanya
  local prev="${rest##*.}"        # segmen kedua dari belakang
  local path="$(printf '%s' "$core" | tr '.' '/')"
  local c1="$(first_char "$last")"
  local p1="$(first_char "$prev")"

  case "$c1" in
    [a-z]*)
      case "$p1" in
        [A-Z]*)
          # Method: com.example.app.Util.encrypt -> com/example/app/Util;encrypt\(.*
          local cls_path="$(printf '%s' "$rest" | tr '.' '/')"
          printf '%s%s;%s\\(.*\n' "$neg" "$cls_path" "$last"
          ;;
        *)
          # Package: com.example.app -> com/example/app/.*;.*
          printf '%s%s/.*;.*\n' "$neg" "$path"
          ;;
      esac
      ;;
    *)
      # Class: com.example.app.MainActivity -> com/example/app/MainActivity;.*
      printf '%s%s;.*\n' "$neg" "$path"
      ;;
  esac
  return 0
}

# ------------------------------------------------------------- state ------
save_state() { # $1 = key, $2 = value
  mkdir -p "$STATE_DIR"
  printf '%s' "$2" > "$STATE_DIR/$1"
}
load_state() {
  [ -d "$STATE_DIR" ] || die "State tidak ditemukan. Jalankan 'prepare' dulu."
  PKG="$(cat "$STATE_DIR/package")"
  PKG_PATH="$(cat "$STATE_DIR/pkg_path")"
  PKG_US="$(cat "$STATE_DIR/pkg_us")"
  JNI_PREFIX="$(cat "$STATE_DIR/jni_prefix")"
  LIB_NAME="$(cat "$STATE_DIR/lib_name")"
  APK_PATH="$(cat "$STATE_DIR/apk_path")"
  [ -n "$PKG" ] || die "State package kosong."
}

resolve_apk() {
  if [ -z "$INPUT_APK" ]; then
    local found=""
    found="$(find . -maxdepth 3 -type f -iname "*.apk" -not -path "./work/*" -not -path "./output/*" -not -path "./tools/*" | sort | head -n 1 || true)"
    [ -n "$found" ] || die "APK tidak ditemukan. Set INPUT_APK."
    INPUT_APK="${found#./}"
  fi
  [ -f "$INPUT_APK" ] || die "APK tidak ditemukan: $INPUT_APK"
  # validasi: harus file zip yang valid
  unzip -l "$INPUT_APK" >/dev/null 2>&1 || die "$INPUT_APK bukan file APK/zip yang valid."
  APK_PATH="$INPUT_APK"
  log "Menggunakan APK input: $APK_PATH"
}

find_aapt() {
  local base
  for base in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" "/usr/local/lib/android/sdk"; do
    [ -n "$base" ] || continue
    local f
    f="$(find "$base/build-tools" -maxdepth 2 -type f -name aapt 2>/dev/null | sort -V | tail -n 1 || true)"
    if [ -n "$f" ]; then printf '%s' "$f"; return 0; fi
  done
  return 1
}

# ------------------------------------------------------- mode: prepare ----
build_filter() {
  mkdir -p "$DEX2C_DIR"
  local filter="$DEX2C_DIR/filter.txt"
  {
    echo "# filter.txt — dibuat otomatis oleh protect-apk.sh"
    echo "# package: $PKG"
    echo "# dibuat: $(date -u +%FT%TZ)"
    echo ""
    echo "# ===== whitelist ====="
    if [ -n "$INPUT_INCLUDE" ]; then
      printf '%s\n' "$INPUT_INCLUDE" | while IFS= read -r line || [ -n "$line" ]; do
        to_rule "$line" || true
      done
    else
      printf '%s/.*;.*\n' "$PKG_PATH"
    fi
    echo ""
    echo "# ===== blacklist bawaan (R & BuildConfig tidak aman diprotect) ====="
    printf '!%s/R.*;.*\n' "$PKG_PATH"
    printf '!%s/BuildConfig;.*\n' "$PKG_PATH"
    if [ -n "$INPUT_EXCLUDE" ]; then
      echo "# ===== blacklist dari user ====="
      printf '%s\n' "$INPUT_EXCLUDE" | while IFS= read -r line || [ -n "$line" ]; do
        to_rule "$line" || true
      done
    fi
    if [ -s "$EXCLUDE_FILE" ]; then
      echo "# ===== blacklist otomatis (method yang bikin C++ dex2c rusak) ====="
      cat "$EXCLUDE_FILE"
    fi
  } > "$filter"
  local n
  n="$(grep -c -v -e '^\s*#' -e '^\s*$' "$filter" || true)"
  log "filter.txt ditulis ($n aturan):"
  grep -v -e '^\s*#' -e '^\s*$' "$filter" | head -n 40 || true
}

cmd_prepare() {
  resolve_apk
  rm -rf "$WORK_DIR" "$OUTPUT_DIR"
  mkdir -p "$WORK_DIR" "$OUTPUT_DIR" "$STATE_DIR" tools

  local pkg="$INPUT_PACKAGE"
  if [ -z "$pkg" ]; then
    local aapt_bin=""
    aapt_bin="$(find_aapt)" || die "aapt tidak ditemukan & INPUT_PACKAGE kosong. Isi package name manual."
    log "Auto-deteksi package via aapt..."
    pkg="$("$aapt_bin" dump badging "$APK_PATH" 2>/dev/null | sed -n "s/^package: name='\([^']*\)'.*/\1/p" | head -n 1)"
    [ -n "$pkg" ] || die "Gagal mendeteksi package name dari APK."
  fi
  # validasi format package
  case "$pkg" in
    *[!a-zA-Z0-9._]*|""|.*|*..*|*.)
      die "Package name tidak valid: '$pkg'" ;;
  esac
  log "Package: $pkg"

  local pkg_path="$(printf '%s' "$pkg" | tr '.' '/')"
  local pkg_us="$(printf '%s' "$pkg" | tr '.' '_')"
  local jni_prefix="Java_${pkg_us}_"
  local lib_name="$INPUT_LIB_NAME"
  if [ -z "$lib_name" ]; then
    lib_name="$(printf '%s' "$pkg" | tr -cd 'a-zA-Z0-9' | tr 'A-Z' 'a-z')"
    [ -n "$lib_name" ] || lib_name="dex2cprotected"
  fi
  # nama modul NDK: huruf kecil, alnum + underscore
  lib_name="$(printf '%s' "$lib_name" | tr -cd 'a-zA-Z0-9_' | tr 'A-Z' 'a-z')"
  [ -n "$lib_name" ] || die "LIB_NAME kosong setelah sanitasi."

  # validasi format custom loader: harus package.Class
  case "$INPUT_CUSTOM_LOADER" in
    *.*)
      case "$INPUT_CUSTOM_LOADER" in
        *[!a-zA-Z0-9._]*|""|.*|*..*|*.)
          die "INPUT_CUSTOM_LOADER tidak valid: '$INPUT_CUSTOM_LOADER'" ;;
      esac ;;
    *)
      die "INPUT_CUSTOM_LOADER harus format package.Class, mis. miku.moe.app.DccApplication" ;;
  esac
  log "Loader class dex2c: $INPUT_CUSTOM_LOADER"

  save_state package    "$pkg"
  save_state pkg_path   "$pkg_path"
  save_state pkg_us     "$pkg_us"
  save_state jni_prefix "$jni_prefix"
  save_state lib_name   "$lib_name"
  save_state apk_path   "$APK_PATH"

  PKG="$pkg"; PKG_PATH="$pkg_path"; JNI_PREFIX="$jni_prefix"; LIB_NAME="$lib_name"
  log "Native lib: lib${lib_name}.so | JNI prefix: ${jni_prefix}"

  build_filter
  local n
  n="$(grep -c -v -e '^\s*#' -e '^\s*$' "$DEX2C_DIR/filter.txt" || true)"
  progress 34 "Filter proteksi siap ($n aturan, package $pkg)"
}

# --------------------------------------------------------- mode: setup ----
patch_dcc() {
  # Patch dex2c: perbaiki jvalue initializer yang kadang digenerate rusak
  # (logika dari script asli user — bersifat generik, tidak tergantung package).
  python3 - <<'PY'
from pathlib import Path

path = Path("dcc.py")
text = path.read_text(encoding="utf-8")
marker = "def build_project(project_dir):\n"
helper = r'''
def patch_dex2c_generated_cpp(project_dir):
    import re
    from pathlib import Path
    fields = {
        "jboolean": "z",
        "jbyte": "b",
        "jchar": "c",
        "jshort": "s",
        "jint": "i",
        "jlong": "j",
        "jfloat": "f",
        "jdouble": "d"
    }
    root = Path(project_dir)
    total = 0
    for cpp in root.rglob("*.cpp"):
        try:
            data = cpp.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            data = cpp.read_text(errors="ignore")
        declarations = {}
        for typ, name in re.findall(r"\b(jboolean|jbyte|jchar|jshort|jint|jlong|jfloat|jdouble)\s+([A-Za-z_]\w*)\b", data):
            declarations[name] = fields[typ]
        changed = 0
        def fix_jvalue(match):
            nonlocal changed
            old_field = match.group(1)
            name = match.group(2)
            new_field = declarations.get(name)
            if new_field and old_field != new_field:
                changed += 1
                return "{." + new_field + " = " + name + "}"
            return match.group(0)
        patched = re.sub(r"\{\s*\.\s*([A-Za-z])\s*=\s*([A-Za-z_]\w*)\s*\}", fix_jvalue, data)
        if patched != data:
            cpp.write_text(patched, encoding="utf-8")
            total += changed
    if total:
        print("[INFO    ] dcc: Patched", total, "jvalue initializer field(s)")
'''

if marker not in text:
    raise SystemExit("build_project tidak ditemukan di dcc.py")

if "def patch_dex2c_generated_cpp(project_dir):" not in text:
    text = text.replace(marker, helper + "\n" + marker, 1)

patched_marker = "def build_project(project_dir):\n    patch_dex2c_generated_cpp(project_dir)\n"
if patched_marker not in text:
    text = text.replace(marker, patched_marker, 1)

path.write_text(text, encoding="utf-8")
print("[protect-apk] dcc.py terpatch.")
PY
}

resolve_ndk() {
  NDK_DIR="${ANDROID_NDK_HOME:-}"
  if [ -z "$NDK_DIR" ] || [ ! -d "$NDK_DIR" ]; then
    local cand
    for cand in "${ANDROID_HOME:-}/ndk/$NDK_VERSION" "${ANDROID_SDK_ROOT:-}/ndk/$NDK_VERSION" \
               "/usr/local/lib/android/sdk/ndk/$NDK_VERSION"; do
      if [ -n "$cand" ] && [ -d "$cand" ]; then NDK_DIR="$cand"; break; fi
    done
  fi
  if { [ -z "$NDK_DIR" ] || [ ! -d "$NDK_DIR" ]; } then
    local base
    for base in "${ANDROID_HOME:-}/ndk" "${ANDROID_SDK_ROOT:-}/ndk" "/usr/local/lib/android/sdk/ndk"; do
      if [ -n "$base" ] && [ -d "$base" ]; then
        NDK_DIR="$(find "$base" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -V | tail -n 1 || true)"
        if [ -n "$NDK_DIR" ] && [ -d "$NDK_DIR" ]; then break; fi
      fi
    done
  fi
  [ -n "$NDK_DIR" ] && [ -d "$NDK_DIR" ] || die "ANDROID_NDK_HOME tidak ditemukan."
  export ANDROID_NDK_HOME="$NDK_DIR"
  log "NDK: $NDK_DIR"
  if [ -n "${GITHUB_ENV:-}" ]; then
    printf 'ANDROID_NDK_HOME=%s\n' "$NDK_DIR" >> "$GITHUB_ENV"
  fi
}

resolve_zipalign() {
  local base f
  for base in "${ANDROID_HOME:-}/build-tools" "${ANDROID_SDK_ROOT:-}/build-tools" "/usr/local/lib/android/sdk/build-tools"; do
    [ -n "$base" ] && [ -d "$base" ] || continue
    f="$(find "$base" -type f -name zipalign 2>/dev/null | sort -V | tail -n 1 || true)"
    if [ -n "$f" ]; then
      export PATH="$(dirname "$f"):$PATH"
      log "zipalign: $f"
      if [ -n "${GITHUB_PATH:-}" ]; then
        printf '%s\n' "$(dirname "$f")" >> "$GITHUB_PATH"
      fi
      return 0
    fi
  done
  die "zipalign tidak ditemukan."
}

write_dcc_cfg() {
  python3 - <<PY
import json
from pathlib import Path
cfg = {
    "apktool": "tools/apktool.jar",
    "ndk_dir": "$NDK_DIR",
    "signature": {
        "keystore_path": "keystore/debug.keystore",
        "alias": "androiddebugkey",
        "keystore_pass": "android",
        "store_pass": "android",
        "v1_enabled": True,
        "v2_enabled": True,
        "v3_enabled": True,
    },
    "ollvm": {"enable": False, "flags": "-fvisibility=hidden"},
}
p = Path("$DEX2C_DIR/dcc.cfg")
p.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
json.loads(p.read_text(encoding="utf-8"))
print("[protect-apk] dcc.cfg ditulis.")
PY
}

write_mk_files() {
  local abi
  case "$INPUT_ARCH" in
    arm64) abi="arm64-v8a" ;;
    armv7) abi="armeabi-v7a" ;;
    *)     abi="armeabi-v7a arm64-v8a" ;;
  esac
  {
    echo "APP_STL := c++_static"
    echo "APP_CPPFLAGS += -fvisibility=hidden"
    echo "APP_PLATFORM := android-19"
    echo "APP_ABI := $abi"
    echo "APP_SHORT_COMMANDS := true"
  } > "$DEX2C_DIR/project/jni/Application.mk"
  log "Application.mk ditulis (APP_ABI := $abi)."

  cat > "$DEX2C_DIR/project/jni/Android.mk" <<EOF_MK
LOCAL_PATH:= \$(call my-dir)

include \$(CLEAR_VARS)
LOCAL_MODULE := ${LIB_NAME}
LOCAL_LDLIBS := -llog
LOCAL_LDFLAGS += "-Wl,-z,max-page-size=16384"
SOURCES := \$(wildcard \$(LOCAL_PATH)/nc/*.cpp)
LOCAL_C_INCLUDES := \$(LOCAL_PATH)/nc
LOCAL_SRC_FILES := \$(SOURCES:\$(LOCAL_PATH)/%=%)
LOCAL_SHORT_COMMANDS := true
include \$(BUILD_SHARED_LIBRARY)
EOF_MK
  log "Android.mk ditulis (LOCAL_MODULE := ${LIB_NAME})."
}

cmd_setup() {
  load_state
  mkdir -p tools

  if [ ! -f "$DEX2C_DIR/dcc.py" ]; then
    log "Clone dex2c..."
    rm -rf "$DEX2C_DIR"
    git clone --depth 1 https://github.com/codehasan/dex2c.git "$DEX2C_DIR"
  else
    log "dex2c sudah ada, pakai yang lokal."
  fi

  ( cd "$DEX2C_DIR" && patch_dcc )
  progress 38 "dex2c siap, install Python requirements..."

  ( cd "$DEX2C_DIR" && python3 -m pip install --quiet --upgrade pip && python3 -m pip install --quiet -r requirements.txt )
  log "Python requirements terinstall."

  mkdir -p "$DEX2C_DIR/tools"
  if [ ! -s "$DEX2C_DIR/tools/apktool.jar" ]; then
    log "Download apktool v${APKTOOL_VERSION}..."
    if ! curl -L --fail -o "$DEX2C_DIR/tools/apktool.jar" \
        "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar"; then
      log "Fallback ke apktool v${APKTOOL_FALLBACK_VERSION}..."
      curl -L --fail -o "$DEX2C_DIR/tools/apktool.jar" \
        "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_FALLBACK_VERSION}/apktool_${APKTOOL_FALLBACK_VERSION}.jar"
    fi
  fi
  test -s "$DEX2C_DIR/tools/apktool.jar" || die "apktool.jar gagal didownload."
  java -jar "$DEX2C_DIR/tools/apktool.jar" --version

  resolve_ndk
  write_dcc_cfg
  write_mk_files
  resolve_zipalign
  progress 42 "Setup dex2c & apktool selesai"
}

# -------------------------------------------------------- mode: protect ---
# Pantau log dcc.py dan ubah jadi marker [PROGRESS NN%].
DETECTED_STAGE=""

detect_stage() { # $1 = file log ; memakai & mengubah DETECTED_STAGE
  local logf="$1"
  [ -f "$logf" ] || return 0
  # cek dari tahap paling akhir ke awal (log bersifat kumulatif)
  if [ "$DETECTED_STAGE" != "zip" ] && grep -q "Zipaligning" "$logf" 2>/dev/null; then
    progress 86 "Zipalign APK..."; DETECTED_STAGE="zip"; return 0
  fi
  if [ "$DETECTED_STAGE" != "built" ] && [ "$DETECTED_STAGE" != "zip" ] \
     && grep -q "I: Building apk" "$logf" 2>/dev/null; then
    progress 80 "Rebuild APK (apktool)..."; DETECTED_STAGE="built"; return 0
  fi
  case "$DETECTED_STAGE" in built|zip) return 0 ;; esac
  if grep -q "I: Decoding" "$logf" 2>/dev/null; then
    if [ "$DETECTED_STAGE" != "decomp" ]; then
      progress 74 "Decompile APK (apktool)..."; DETECTED_STAGE="decomp"
    fi
    return 0
  fi
  if grep -q -e "Install " -e "SharedLibrary" "$logf" 2>/dev/null; then
    if [ "$DETECTED_STAGE" != "link" ]; then
      progress 70 "Linking native library..."; DETECTED_STAGE="link"
    fi
    return 0
  fi
  if grep -q "Compile++" "$logf" 2>/dev/null; then
    if [ "$DETECTED_STAGE" != "compile" ]; then
      progress 64 "Mengkompilasi native library (NDK)..."; DETECTED_STAGE="compile"
    fi
    return 0
  fi
  if grep -q "Overwrite file" "$logf" 2>/dev/null; then
    if [ "$DETECTED_STAGE" != "wrote" ]; then
      progress 56 "Menulis kode native C++..."; DETECTED_STAGE="wrote"
    fi
    return 0
  fi
  if grep -q "Adjusting Application.mk" "$logf" 2>/dev/null; then
    if [ "$DETECTED_STAGE" != "mk" ]; then
      progress 50 "Menyesuaikan Application.mk (ABI)..."; DETECTED_STAGE="mk"
    fi
    return 0
  fi
  return 0
}

monitor_progress() { # $1 = file log, $2 = pid dcc.py
  local logf="$1" pid="$2"
  while kill -0 "$pid" 2>/dev/null; do
    detect_stage "$logf"
    sleep 5
  done
  detect_stage "$logf"
}

# Baca error kompilasi C++ dari log, ubah jadi aturan blacklist otomatis.
# Generik: memakai PKG_PATH & JNI prefix dari state (bukan hardcoded).
parse_failed_native_methods() { # $1 = file log
  local logf="$1"
  [ -f "$logf" ] || return 0
  PKG_PATH="$PKG_PATH" PKG_US="$PKG_US" python3 - "$logf" "$EXCLUDE_FILE" <<'PY'
import re, sys
from pathlib import Path

pkg_path = __import__("os").environ["PKG_PATH"]
prefix = "Java_" + __import__("os").environ["PKG_US"] + "_"

log_path = Path(sys.argv[1])
out_path = Path(sys.argv[2])
text = log_path.read_text(errors="ignore") if log_path.exists() else ""

found = []
for filename in sorted(set(re.findall(r"jni/nc/(Java_[^:\s]+\.cpp):\d+:\d+: error:", text))):
    stem = filename[:-4]
    if not stem.startswith(prefix):
        continue
    body = stem[len(prefix):]
    before_sig = body.rsplit("__", 1)[0] if "__" in body else body
    if "_" not in before_sig:
        continue
    cls, method = before_sig.rsplit("_", 1)
    if not cls or not method:
        continue
    # 0003c = '<' , 0003e = '>'  -> konstruktor (<init>/<clinit>): exclude 1 class penuh
    if method.startswith("0003c") or method.startswith("0003e"):
        rule = f"!{pkg_path}/{cls};.*"
    else:
        rule = f"!{pkg_path}/{cls};{method}.*"
    found.append(rule)

existing = set()
if out_path.exists():
    existing = {l.strip() for l in out_path.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()}
new_rules = [r for r in found if r not in existing]
if new_rules:
    with out_path.open("a", encoding="utf-8") as f:
        for r in new_rules:
            f.write(r + "\n")
    print("Menambahkan blacklist otomatis (C++ dex2c rusak):")
    for r in new_rules:
        print("  " + r)
else:
    print("Tidak ada blacklist baru dari error C++.")
PY
}

run_dcc_attempt() { # $1 = nomor percobaan ; return status dcc.py
  local logf="$WORK_DIR/dex2c-attempt.log"
  pushd "$DEX2C_DIR" >/dev/null
  rm -f output.apk
  rm -rf .tmp
  # --force-keep-libs: JANGAN timpa APP_ABI dari Application.mk dengan ABI
  # yang ada di APK asli. Hanya ABI pilihan user yang dikompilasi (lebih cepat).
  # --custom-loader: ganti amimo.dcc.DccApplication bawaan dex2c dengan kelas
  # loader branding sendiri (mis. miku.moe.app.DccApplication).
  local args=(-a input.apk -o output.apk --disable-signing --force-keep-libs
             --custom-loader "$INPUT_CUSTOM_LOADER")
  [ "$INPUT_OBFUSCATE" = "true" ] && args+=(-p)
  [ "$INPUT_DYNAMIC_REGISTER" = "true" ] && args+=(-d)
  : > "../../$logf"
  # dcc.py memakai relative path (tools/, project/, filter.txt) -> biarkan cwd di DEX2C_DIR
  python3 dcc.py "${args[@]}" >>"../../$logf" 2>&1 &
  local dcc_pid=$!
  popd >/dev/null
  monitor_progress "$logf" "$dcc_pid"
  wait "$dcc_pid"
  return $?
}

# Daftar ABI yang dipertahankan sesuai INPUT_ARCH.
keep_abis() {
  case "$INPUT_ARCH" in
    arm64) printf 'arm64-v8a' ;;
    armv7) printf 'armeabi-v7a' ;;
    *)     printf 'armeabi-v7a arm64-v8a' ;;
  esac
}

# Hapus folder lib/<abi> yang TIDAK dipilih user dari APK hasil dcc.py.
# (dcc.py selalu membawa semua folder lib/ asli APK; tanpa ini APK final
#  tetap berisi full arsitektur.)
strip_unselected_abis() { # $1 = path apk
  local apk="$1" keep abi entry removed=0
  keep="$(keep_abis)"
  log "ABI dipertahankan: $keep"
  local abis
  abis="$(unzip -l "$apk" 2>/dev/null | awk '{print $4}' | grep '^lib/' | cut -d/ -f2 | sort -u || true)"
  [ -n "$abis" ] || { log "Tidak ada folder lib/ di APK."; return 0; }
  for abi in $abis; do
    case " $keep " in
      *" $abi "*)
        log "ABI dipertahankan: lib/$abi" ;;
      *)
        log "Menghapus ABI tak dipilih: lib/$abi"
        zip -q -d "$apk" "lib/$abi/*" >/dev/null 2>&1 || true
        removed=1 ;;
    esac
  done
  if [ "$removed" = "1" ]; then
    log "Folder ABI tak dipilih sudah dihapus."
  else
    log "Tidak ada ABI tak dipilih yang perlu dihapus."
  fi
}

cmd_protect() {
  load_state
  [ -f "$APK_PATH" ] || die "APK tidak ditemukan: $APK_PATH"
  cp "$APK_PATH" "$DEX2C_DIR/input.apk"
  : > "$EXCLUDE_FILE"

  local attempt max="$INPUT_MAX_ATTEMPTS" success=0 dcc_status=0
  for attempt in $(seq 1 "$max"); do
    build_filter
    progress 46 "Menjalankan dex2c (percobaan $attempt/$max)..."
    log "Filter dipakai:"
    grep -v -e '^\s*#' -e '^\s*$' "$DEX2C_DIR/filter.txt" | head -n 30 || true

    set +e
    run_dcc_attempt "$attempt"
    dcc_status=$?
    set -e

    cat "$WORK_DIR/dex2c-attempt.log" >> "$WORK_DIR/dex2c.log"
    if [ "$dcc_status" -eq 0 ] && [ -f "$DEX2C_DIR/output.apk" ]; then
      success=1
      break
    fi
    log "Percobaan $attempt gagal (exit=$dcc_status). Menganalisis error C++..."
    parse_failed_native_methods "$WORK_DIR/dex2c-attempt.log"
    if [ "$attempt" -eq "$max" ]; then
      log "=== 240 baris terakhir log ==="
      tail -n 240 "$WORK_DIR/dex2c-attempt.log" || true
      die "dex2c gagal setelah $max percobaan."
    fi
    progress 48 "Mencoba lagi dengan blacklist tambahan..."
  done

  [ "$success" = "1" ] || die "dex2c gagal membuat output.apk"
  progress 88 "dex2c selesai. Merapikan ABI & zipalign..."

  local unsigned_apk="$WORK_DIR/app-protected-unsigned-pre.apk"
  cp "$DEX2C_DIR/output.apk" "$unsigned_apk"

  # Hapus folder lib/ arsitektur yang tidak dipilih user (sebelum zipalign)
  strip_unselected_abis "$unsigned_apk"

  local zipalign_help=""
  zipalign_help="$(zipalign 2>&1 || true)"
  if printf '%s\n' "$zipalign_help" | grep -q -- "-P <pagesize_kb>"; then
    zipalign -P 16 -f 4 "$unsigned_apk" "$FINAL_APK"
  else
    zipalign -p -f 4 "$unsigned_apk" "$FINAL_APK"
  fi
  test -f "$FINAL_APK" || die "zipalign gagal."

  # verifikasi: .so dex2c ada di SETIAP ABI yang dipilih user,
  # dan tidak ada folder ABI lain di APK final.
  local so_name="lib${LIB_NAME}.so" keep_abi
  for keep_abi in $(keep_abis); do
    unzip -l "$FINAL_APK" | grep -q "lib/$keep_abi/$so_name" \
      || { unzip -l "$FINAL_APK" | grep -e 'lib/.*\.so' || true; die "$so_name tidak ada di lib/$keep_abi APK final."; }
  done
  local extra_abis
  extra_abis="$(unzip -l "$FINAL_APK" 2>/dev/null | awk '{print $4}' | grep '^lib/' | cut -d/ -f2 | sort -u || true)"
  for abi in $extra_abis; do
    case " $(keep_abis) " in
      *" $abi "*) ;;
      *) die "ABI tak dipilih masih ada di APK final: lib/$abi" ;;
    esac
  done
  log "Verifikasi ABI OK: hanya [$(keep_abis)] di APK final."

  local sym_count="0"
  sym_count="$(unzip -p "$FINAL_APK" "lib/*/$so_name" 2>/dev/null | strings | grep -c "$JNI_PREFIX" || true)"
  log "Jumlah symbol native ${JNI_PREFIX}: ${sym_count:-0}"
  [ "${sym_count:-0}" -gt 0 ] || die "Tidak ada symbol native $JNI_PREFIX di APK final."

  if [ -s "$EXCLUDE_FILE" ]; then
    log "Method yang di-blacklist otomatis karena C++ dex2c rusak:"
    cat "$EXCLUDE_FILE"
  fi

  ls -lh "$FINAL_APK"
  progress 95 "APK terproteksi & terverifikasi: $FINAL_APK"
}

# -------------------------------------------------------- mode: cleanup ---
cmd_cleanup() {
  [ "$INPUT_CLEANUP" = "true" ] || { log "Cleanup dilewati (INPUT_CLEANUP=false)."; return 0; }
  [ -n "$INPUT_APK" ] || { log "INPUT_APK kosong, cleanup dilewati."; return 0; }
  [ -d .git ] || { log "Bukan repo git, cleanup dilewati."; return 0; }

  git config user.name  "apk-protect-bot"  >/dev/null 2>&1 || true
  git config user.email "apk-protect-bot@local" >/dev/null 2>&1 || true
  if git ls-files --error-unmatch "$INPUT_APK" >/dev/null 2>&1; then
    git rm -q "$INPUT_APK"
    git commit -qm "cleanup: hapus $INPUT_APK setelah diprotect [skip ci]" || true
    local i
    for i in 1 2 3; do
      if git push -q origin "HEAD:$CLEANUP_REF"; then
        log "Cleanup push berhasil."
        progress 98 "APK input dihapus dari repo"
        return 0
      fi
      log "Push cleanup gagal (percobaan $i), pull --rebase dulu..."
      git pull -q --rebase origin "$CLEANUP_REF" || true
    done
    log "Peringatan: push cleanup gagal setelah 3x percobaan."
  else
    log "$INPUT_APK tidak ter-track di git, cleanup dilewati."
  fi
}

# ---------------------------------------------------------------- main ----
case "$MODE" in
  prepare) cmd_prepare ;;
  setup)   cmd_setup ;;
  protect) cmd_protect ;;
  cleanup) cmd_cleanup ;;
  *)
    echo "Pakai: $0 {prepare|setup|protect|cleanup}" >&2
    exit 2
    ;;
esac
