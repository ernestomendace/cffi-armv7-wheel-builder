#!/usr/bin/env bash
set -euo pipefail

IMAGE='quay.io/pypa/manylinux_2_31_armv7l@sha256:ecb0b7cd6db693d46a399226fd93cfd0d01d0dfbf9c65a8d5a0f6821767178fe'
docker pull --platform linux/arm/v7 "$IMAGE"
docker run --rm --platform linux/arm/v7 \
  --volume "$PWD:/work:rw" --workdir /work \
  "$IMAGE" /bin/bash /work/build-inside.sh
