#!/bin/bash

# The challenge relies heavily on specific optimization flags, so build it in a container

set -e
echo "[*] Obtaining libc"
# Ubuntu 22.04
docker_id=$(docker run --rm --detach ubuntu@sha256:ed1544e454989078f5dec1bfdabd8c5cc9c48e0705d07b678ab6ae3fb61952d2 sleep 5)
mkdir -p challenge/glibc
docker cp $docker_id:/lib/x86_64-linux-gnu/libc.so.6 challenge/glibc/
docker cp $docker_id:/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 challenge/glibc/

echo "[*] Compiling challenge"
docker_id=$(cat <<EOF | docker build -q -
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y build-essential && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1000 builder
USER 1000
CMD ["make", "-C", "/mnt/src"]
EOF
)
docker run --rm -v "$(pwd)/src:/mnt/src" "$docker_id"

patchelf --set-rpath ./glibc/ --set-interpreter ./glibc/ld-linux-x86-64.so.2 ./src/vault
