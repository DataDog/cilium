# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

# distroless images are signed by cosign and can be verified using:
# $ cosign verify $IMAGE_NAME --certificate-oidc-issuer https://accounts.google.com --certificate-identity keyless@distroless.iam.gserviceaccount.com
ARG BASE_IMAGE=gcr.io/distroless/static:nonroot@sha256:c0f429e16b13e583da7e5a6ec20dd656d325d88e6819cafe0adb0828976529dc
# These SHA256 digests are important for two reasons:
# 1. They 'pin' the container image to a specific version. Unlike a tag that can be changed at any future point, a
#    SHA265 hash cannot be modified. This increases the security of the build by protecting against a class of supply
#    chain attacks where an attacker has write access to our 3rd party dependency image registries.
# 2. These digests must be to the *overall* digest, not the digest for a specific image. This is because the images will
#    be architecture specific, but the overall digest will contain all of the architectures.
ARG GOLANG_IMAGE=docker.io/library/golang:1.23.8@sha256:4f3bd60d27939f3a280fbcd6de1e174eb163e8108ea86267a2824357dc78a3e7
# We don't use ETCD_IMAGE because that's used in Makefile.defs to select a ETCD image approrpate for the *host platform*
# to run tests with.
ARG ETCD_SERVER_IMAGE=gcr.io/etcd-development/etcd:v3.5.21@sha256:fd158fbe55240e252947bbd2e8dddc217997ff43978071fac2bd202b6ad15c03

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} AS builder

# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
# MODIFIERS are extra arguments to be passed to make at build time.
ARG MODIFIERS

WORKDIR /go/src/github.com/cilium/cilium/clustermesh-apiserver

# We must override NOSTRIP=1 to ensure binaries include debug symbols for extraction. They will be stripped subsequently
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    mkdir -p /out/${TARGETOS}/${TARGETARCH} && cp etcd-config.yaml /out/${TARGETOS}/${TARGETARCH}/etcd-config.yaml
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    make GOARCH=${TARGETARCH} $(echo $MODIFIERS | tr -d '"') NOSTRIP=1 \
    && mkdir -p /out/${TARGETOS}/${TARGETARCH}/usr/bin && mv clustermesh-apiserver /out/${TARGETOS}/${TARGETARCH}/usr/bin

WORKDIR /go/src/github.com/cilium/cilium
# licenses-all is a "script" that executes "go run" so its ARCH should be set
# to the same ARCH specified in the base image of this Docker stage (BUILDARCH)
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    make GOARCH=${BUILDARCH} licenses-all && mv LICENSE.all /out/${TARGETOS}/${TARGETARCH}

# Extract debug symbols to /tmp/debug and strip the binaries if NOSTRIP is not set.
RUN set -xe && \
    export D=/tmp/debug/${TARGETOS}/${TARGETARCH} && \
    objcopy --only-keep-debug ${0} ${0}.debug && \
    if ! echo "$MODIFIERS" | grep "NOSTRIP=1" ; then objcopy --strip-all ${0} && (cd $(dirname ${0}) && objcopy --add-gnu-debuglink=${filename}.debug ${filename}) ; fi && \
    mkdir -p $(dirname ${D}/${0}) && \
    mv -v ${0}.debug ${D}/${0}.debug' \
    {} \;

# Check debug symbols are present
RUN for f in $(find /tmp/debug -type f -name '*.debug' -not -name 'debug-wrapper.debug') ; do readelf -S ${f} | grep -q \\.symtab || \
    (echo Debug symbols are missing in ${f} - possibly due to incorrect build parameters && false); done

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} AS gops

# build-gops.sh will build both archs at the same time
WORKDIR /go/src/github.com/cilium/cilium/images/runtime
RUN apt-get update && apt-get install -y binutils-aarch64-linux-gnu binutils-x86-64-linux-gnu
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    ./build-gops.sh

FROM --platform=${TARGETARCH} ${ETCD_SERVER_IMAGE} AS etcd

FROM ${BASE_IMAGE} AS release
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
LABEL maintainer="maintainer@cilium.io"
COPY --from=gops /out/${TARGETOS}/${TARGETARCH}/bin/gops /bin/gops
# While the etcd image uses /usr/local/bin, we're moving it to /usr/bin to keep consistency with the rest of our images.
# We also don't grab the etcdctl or etcdutl binaries, as we don't need them for our application.
COPY --from=etcd /usr/local/bin/etcd /usr/bin/etcd
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/etcd-config.yaml /var/lib/cilium/etcd-config.yaml
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/bin/clustermesh-apiserver /usr/bin/clustermesh-apiserver
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/LICENSE.all /LICENSE.all

# Configure gops to use a temporary directory, to prevent permission
# issues depending on the UID configured to run the entrypoint.
ENV GOPS_CONFIG_DIR=/tmp/gops

ENTRYPOINT ["/usr/bin/clustermesh-apiserver"]

FROM --platform=${BUILDPLATFORM} ${CILIUM_BUILDER_IMAGE} AS debug-tools

#
# Cilium Clustermesh-apiserver debug image.
#
# Typical image builds will stop above at the 'release' target, but
# developers follow this Dockerfile to the end. Starting from a release
# image, install delve debugger and wrap the cilium-clustermesh-apiserver
# binary calls with a script that automatically provisions the debugger
# on a dedicated port.
FROM release AS debug
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
ARG DEBUG_HOLD
ENV DEBUG_PORT=2346
ENV DEBUG_HOLD=${DEBUG_HOLD}
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/bin/clustermesh-apiserver /usr/bin/clustermesh-apiserver-bin
COPY --from=debug-tools /go/bin/dlv /usr/bin/dlv
COPY --from=debug-tools /out/${TARGETOS}/${TARGETARCH}/bin/debug-wrapper /usr/bin/clustermesh-apiserver

# Copy in the debug symbols in case the binaries were stripped
COPY --from=builder /tmp/debug/${TARGETOS}/${TARGETARCH}/ /usr/lib/debug/

# Ensure dlv finds the debug symbols. Due to CGO_ENABLED=0, we have no GNU build-id, so Delve's default search path
# is insufficient.
ADD images/clustermesh-apiserver/dlv-config.yml /root/.config/dlv/config.yml
