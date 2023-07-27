# syntax=docker/dockerfile:1.2

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

# Datadog Modification: Swap to distroless GBI
# doc: https://datadoghq.atlassian.net/wiki/spaces/DEVX/pages/2730986360/Living+doc+How+to+migrate+to+Golden+Base+Images
ARG BASE_IMAGE=registry.ddbuild.io/images/base/gbi-distroless:latest@sha256:be05d4c795fa14da8c21ef40f0f4dd257095adf204a44e2b24676a92c03ea52d
# Datadog Modification: Swap to internal registry for images & use 1.18 image instead
ARG GOLANG_IMAGE=registry.ddbuild.io/images/mirror/golang:1.18@sha256:5620e1858683c335bc7c710614f3949b6dc75f6578163c08f78db2c40087e2e1
# Datadog Modification: Swap to internal registry for images & use 3.16 image instead
ARG ALPINE_IMAGE=registry.ddbuild.io/images/mirror/alpine:3.16@sha256:4139bde241059fc2f22decac1fa663fc9ab58ba161bd0ab301ccfce7962b92fd

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} as builder

# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
ARG NOSTRIP
ARG NOOPT
ARG LOCKDEBUG
ARG RACE
# Datadog Modification: Hardcode just 'operator' to build a general operator for aws,azure,etc.
ARG OPERATOR_VARIANT=operator

WORKDIR /go/src/github.com/cilium/cilium/operator

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    make GOARCH=${TARGETARCH} RACE=${RACE} NOSTRIP=${NOSTRIP} NOOPT=${NOOPT} LOCKDEBUG=${LOCKDEBUG} cilium-${OPERATOR_VARIANT} \
    && mkdir -p /out/${TARGETOS}/${TARGETARCH}/usr/bin && mv cilium-${OPERATOR_VARIANT} /out/${TARGETOS}/${TARGETARCH}/usr/bin

WORKDIR /go/src/github.com/cilium/cilium
# licenses-all is a "script" that executes "go run" so its ARCH should be set
# to the same ARCH specified in the base image of this Docker stage (BUILDARCH)
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    make GOARCH=${BUILDARCH} licenses-all && mv LICENSE.all /out/${TARGETOS}/${TARGETARCH}

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${ALPINE_IMAGE} as certs
RUN apk --update add ca-certificates

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} as gops

# build-gops.sh will build both archs at the same time
WORKDIR /go/src/github.com/cilium/cilium/images/runtime
# Datadog Modification: Add --no-install-recommends per hadolint
RUN apt-get update && apt-get install --no-install-recommends -y binutils-aarch64-linux-gnu binutils-x86-64-linux-gnu
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium     ./build-gops.sh

FROM ${BASE_IMAGE}

# Datadog Modification: operator has to run as root
USER root

# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
# Datadog Modification: Hardcode just 'operator' to build a general operator for aws,azure,etc.
ARG OPERATOR_VARIANT=operator
LABEL maintainer="maintainer@cilium.io"
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=gops /out/${TARGETOS}/${TARGETARCH}/bin/gops /bin/gops
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/bin/cilium-${OPERATOR_VARIANT} /usr/bin/cilium-${OPERATOR_VARIANT}
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/LICENSE.all /LICENSE.all
WORKDIR /
ENV GOPS_CONFIG_DIR=/
CMD ["/usr/bin/cilium-${OPERATOR_VARIANT}"]