#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail

if [[ ${BASH:-} ]]; then
  # not compatible with alpine's sh
  set -o errtrace
  cd "$(dirname "${BASH_SOURCE}")/../.."
fi

: "${BUILD_IMAGE_NAME:=quay.io/travelping/upf-build}"
: "${PUSH_BUILD_IMAGE:=}"

build_hash="$(git ls-tree HEAD -- Makefile build/external extras/docker/Dockerfile.build | md5sum | awk '{print $1}')"
build_image="${BUILD_IMAGE_NAME}:${build_hash}"

if [[ ! $(docker images -q "${build_image}") ]] && ! docker pull "${build_image}"; then
  DOCKER_BUILDKIT=1 docker build -f extras/docker/Dockerfile.build -t "${build_image}" .
  if [[ ${PUSH_BUILD_IMAGE} ]]; then
    docker push "${build_image}"
  fi
fi

docker tag "${build_image}" "${BUILD_IMAGE_NAME}"
