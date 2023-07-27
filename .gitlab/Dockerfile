# Docker 20.10.13
FROM registry.ddbuild.io/images/docker@sha256:23643e6da71fc2551046a1928c071e6db5770f050a0f5a1e613168d2c65fb8bc

RUN set -x \
  && apt-get update \
  && apt-get -y install --no-install-recommends make \
  && apt-get -y clean \
  && rm -rf /var/lib/apt/lists/*
