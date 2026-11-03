#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON_BIN="${PYTHON_BIN:-python3.13}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python 3.13 tidak ditemukan. Set PYTHON_BIN ke Python 3.13/3.14 yang tersedia." >&2
  exit 1
fi
if [ ! -d .venv ]; then
  "$PYTHON_BIN" -m venv .venv
fi
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt flet-cli==1.0.4
rm -rf build
flet build apk --build-number 13 --build-version 1.0.1 --python-version 3.13 --project kawaltrace --bundle-id id.kawaltrace.app --product "Kawal Trace" --org id.kawaltrace --artifact Kawal-Trace
mapfile -t APK_FILES < <(find build -type f -name '*.apk' -print)
if [ "${#APK_FILES[@]}" -eq 0 ]; then
  echo "Flet selesai tetapi tidak menghasilkan APK; build dianggap gagal." >&2
  exit 1
fi
printf 'APK ditemukan: %s\n' "${APK_FILES[@]}"
