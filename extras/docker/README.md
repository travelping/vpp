# Docker image building

This directory contains Dockerfiles and helper scripts for building
docker images.

The idea is that there's a 'build image' which is tagged with the hash
of following files / subtrees:

* `Makefile`
* `extras/docker/Dockerfile.build`
* `build/external/`

The image is rebuilt every time one of this files is changed during
the 'prepare' stage of GitLab pipeline.

In order to ensure that the build image is up to date you need to run
the following script, which will try to locate the build image in
docker image list or pull it, and, failing that, build it from
scratch:

```
extras/docker/ensure-build-image.sh
```

Most of the time, you will not need this as `prepare` stage of the
pipelines takes care of that; you may only need this if you change
something related to build dependencies.

The tag for the proper build image must be present in `.gitlab-ci.yml`
and the Dockerfiles. To keep it up to date, you need to invoke the
following script:

```
extras/docker/update-build-image-tag.sh
```

There's also a helper git pre-commit hook that will verify that the
image tags are correct everywhere and ask you to run the above script
if they're not. You can install it like this:

```
extras/docker/install-hooks.sh
```

This hook also helps avoiding commits containing stray debug print.
When you add a temporary debug print via `clib_warning()` or something
else, add `ZZZZZ:` to the message and the hook will prevent you from
committing that code by accident:

```
clib_warning("ZZZZZ: i %d", i);
```

## Building the images

Build release image:

```
DOCKER_BUILDKIT=1 docker build -f extras/docker/Dockerfile -t upf/my .
```

Build debug image:

```
DOCKER_BUILDKIT=1 docker build -f extras/docker/Dockerfile.debug -t upf/my-debug .
```
