#!/usr/bin/env bash
set -euo pipefail

mkdir -p input output
fetch() {
  local url="$1" name="$2" sha="$3"
  curl --fail --silent --show-error --location "$url" -o "input/$name"
  printf '%s  %s\n' "$sha" "input/$name" | sha256sum --check --status
  echo "verified $name"
}

fetch \
  'https://files.pythonhosted.org/packages/eb/56/b1ba7935a17738ae8453301356628e8147c79dbb825bcbc73dc7401f9846/cffi-2.0.0.tar.gz' \
  'cffi-2.0.0.tar.gz' \
  '44d1b5909021139fe36001ae048dbdde8214afa20200eda0f64c068cac5d5529'
fetch \
  'https://files.pythonhosted.org/packages/a9/07/99f2cefae815c66eb23148f15d79ec055429c38fa8986edcc712ab5f3223/setuptools-77.0.3-py3-none-any.whl' \
  'setuptools-77.0.3-py3-none-any.whl' \
  '67122e78221da5cf550ddd04cf8742c8fe12094483749a792d56cd669d6cf58c'
fetch \
  'https://files.pythonhosted.org/packages/0b/2c/87f3254fd8ffd29e4c02732eee68a83a1d3c346ae39bc6822dcbcb697f2b/wheel-0.45.1-py3-none-any.whl' \
  'wheel-0.45.1-py3-none-any.whl' \
  '708e7481cc80179af0e556bbf0cc00b8444c7321e2700b8d8580231d13017248'
fetch \
  'https://files.pythonhosted.org/packages/a0/e3/59cd50310fc9b59512193629e1984c1f95e5c8ae6e5d8c69532ccc65a7fe/pycparser-2.23-py3-none-any.whl' \
  'pycparser-2.23-py3-none-any.whl' \
  'e5c6e8d3fbad53479cab09ac03729e0a9faf2bee3db8208a550daf5af81a5934'
