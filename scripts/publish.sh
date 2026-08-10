#!/usr/bin/env bash
set -euo pipefail

# Builds, tags, and pushes the ARM64 container image to the private registry.
# Usage: ./scripts/publish.sh [tag]

TAG="${1:-latest}"
IMAGE_NAME="unifi-mcp"
REGISTRY="docker-registry.webbman.nyc:443"
FULL_IMAGE="${REGISTRY}/${IMAGE_NAME}:${TAG}"
REPOSITORY_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Building ${IMAGE_NAME}:${TAG}"
docker build \
  --platform linux/arm64 \
  -t "${IMAGE_NAME}:${TAG}" \
  "${REPOSITORY_ROOT}"

echo "==> Tagging ${FULL_IMAGE}"
docker tag "${IMAGE_NAME}:${TAG}" "${FULL_IMAGE}"

echo "==> Pushing ${FULL_IMAGE}"
docker push "${FULL_IMAGE}"

echo "Done."
