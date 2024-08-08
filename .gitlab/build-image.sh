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

# Get the N_GIT_TAGS_TO_BUILD latest git tags containing the dd suffix
GIT_TAGS_TO_BUILD=$(git --no-pager tag --sort=-creatordate --merged HEAD --list \*-dd\* | head -n $N_GIT_TAGS_TO_BUILD)

while IFS= read -r GIT_TAG; do
  git checkout "$GIT_TAG"

  # Construct the image tag
  IMAGE_TAG="$GIT_TAG"
  if [ "$TARGET" = "debug" ]; then
    IMAGE_TAG="${IMAGE_TAG}-debug"
  fi
  if [ "$CI_PIPELINE_SOURCE" == "schedule" ]; then
    TIMESTAMP=${CI_PIPELINE_CREATED_AT//:/-}
    TIMESTAMP=${TIMESTAMP,,}
    IMAGE_TAG="${IMAGE_TAG}-${TIMESTAMP}"
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
    --label CI_PIPELINE_ID="$CI_PIPELINE_ID" \
    --label CI_JOB_ID="$CI_JOB_ID" \
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
      --label CI_PIPELINE_ID="$CI_PIPELINE_ID" \
      --label CI_JOB_ID="$CI_JOB_ID" \
      --target debug \
      --push \
      --metadata-file "$METADATA_FILE_DEBUG" \
      "$DOCKER_CTX"
    ddsign sign "$IMAGE_REF"-debug --docker-metadata-file "$METADATA_FILE_DEBUG"
  fi

  # Save the tags to a file for later use with Campaigner
  printf "%s %s\n" "$GIT_TAG" "$IMAGE_TAG" >> image_tags.txt
done <<< "$GIT_TAGS_TO_BUILD"
