#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail

if [[ ${BASH:-} ]]; then
  # not compatible with alpine's sh
  set -o errtrace
  cd "$(dirname "${BASH_SOURCE}")/../.."
fi

: ${BUILD_IMAGE_NAME:=quay.io/travelping/upf-build}
: ${PUSH_BUILD_IMAGE:=}
: ${USE_BUILDCTL_AND_PUSH:=}
: ${BUILDKITD_ADDR:=tcp://buildkitd:1234}

build_hash="$(git ls-tree HEAD -- Makefile build/external extras/docker/Dockerfile.build | md5sum | awk '{print $1}')"
build_image="${BUILD_IMAGE_NAME}:${build_hash}"

if [[ ! $(docker images -q "${build_image}") ]] && ! docker pull "${build_image}"; then
  if [[ ${USE_BUILDCTL_AND_PUSH} ]]; then
    # FIXME: can't export cache to quay.io:
    # https://github.com/moby/buildkit/issues/1440
    # --export-cache type=inline \
    # --import-cache type=registry,ref="${BUILD_IMAGE_NAME}" \
    buildctl --addr "${BUILDKITD_ADDR}" build \
             --frontend dockerfile.v0 \
             --progress=plain \
             --local context=. \
             --local dockerfile=extras/docker \
             --opt filename=Dockerfile.build \
             --output type=image,name="${build_image}",push=true
  else
    DOCKER_BUILDKIT=1 docker build -f extras/docker/Dockerfile.build -t "${build_image}" .
  fi
fi
