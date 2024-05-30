#!/bin/bash

set -uo pipefail
for GIT_TAG in $(git --no-pager tag --sort=creatordate --merged "$(git rev-parse --abbrev-ref HEAD)" --list 1.13.\*-dd\*  | tail -n 1); do
  echo "cilium:${GIT_TAG}"
  echo "cilium-operator:${GIT_TAG}"
  echo "hubble-relay:${GIT_TAG}"
done
