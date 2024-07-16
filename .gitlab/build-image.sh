#!/usr/bin/env bash
set -exuo pipefail

# Construct valid --build-args arguments from the DOCKER_BUILD_ARGS variable
BUILD_ARGS=""
IFS=$'\n'
for arg in $DOCKER_BUILD_ARGS; do
  BUILD_ARGS+=" $(echo "--build-arg $arg")"
done
IFS=$' '

# Build 3 latest git tags when the pipeline is triggered by a schedule, otherwise build the latest tag
N_GIT_TAGS_TO_BUILD=1
if [ "$CI_PIPELINE_SOURCE" == "schedule" ]; then
  N_GIT_TAGS_TO_BUILD=3
fi

GIT_TAGS_TO_BUILD=$(git tag --sort=-creatordate --merged HEAD | head -n $N_GIT_TAGS_TO_BUILD)

while IFS= read -r GIT_TAG; do
  # Construct the image tag
  IMAGE_TAG="$GIT_TAG"
  if [ "$TARGET" = "debug" ]; then
    IMAGE_TAG="$IMAGE_TAG-debug"
  fi
  if [ "$CI_PIPELINE_SOURCE" == "schedule" ]; then
    IMAGE_TAG="$IMAGE_TAG-$(date +"%Y-%m-%d-%H-%M")"
  fi
  IMAGE_REF="registry.ddbuild.io/$IMAGE_NAME:$IMAGE_TAG"

  # Find the right Cilium Runtime image to use for the main Cilium image build
  if [ "$IMAGE_NAME" == "cilium" ]; then
    CILIUM_RUNTIME_IMAGE="registry.ddbuild.io/cilium-runtime:$IMAGE_TAG"
    BUILD_ARGS+=" --build-arg CILIUM_RUNTIME_IMAGE=$CILIUM_RUNTIME_IMAGE"
  fi

  METADATA_FILE=$(mktemp)
  docker buildx build --platform linux/amd64,linux/arm64 \
    --tag "$IMAGE_REF" \
    --file "$DOCKERFILE_PATH" \
    $BUILD_ARGS \
    --label CILIUM_VERSION="$(cat VERSION)" \
    --label target=prod \
    --target "$TARGET" \
    --push \
    --metadata-file "$METADATA_FILE" \
    "$DOCKER_CTX"

  ddsign sign "$IMAGE_REF" --docker-metadata-file "$METADATA_FILE"

  # Always build the debug version of the Cilium image
  if [ "$IMAGE_NAME" == "cilium" ]; then
    METADATA_FILE_DEBUG=$(mktemp)
    docker buildx build --platform linux/amd64,linux/arm64 \
      --tag "$IMAGE_REF"-debug \
      --file "$DOCKERFILE_PATH" \
      $BUILD_ARGS \
      --label CILIUM_VERSION="$(cat VERSION)" \
      --label target=debug \
      --target debug \
      --push \
      --metadata-file "$METADATA_FILE_DEBUG" \
      "$DOCKER_CTX"
    ddsign sign "$IMAGE_REF"-debug --docker-metadata-file "$METADATA_FILE_DEBUG"
  fi
done <<< "$GIT_TAGS_TO_BUILD"
