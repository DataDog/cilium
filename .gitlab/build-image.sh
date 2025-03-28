#!/usr/bin/env bash
set -exuo pipefail

TARGET="${TARGET:-}"

# Construct valid --build-args arguments from the DOCKER_BUILD_ARGS variable
BUILD_ARGS="--build-arg MODIFIERS=BORINGCRYPTO=1"
IFS=$'\n'
for arg in $DOCKER_BUILD_ARGS; do
    BUILD_ARGS+=" $(echo "--build-arg $arg")"
done
IFS=$' '

IMAGE_NAME=$CI_JOB_NAME
# Construct the image tag
IMAGE_TAG="$CI_COMMIT_TAG"
if [ "$TARGET" = "debug" ]; then
    IMAGE_TAG="${IMAGE_TAG}-debug"
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
    --label is_fips=true \
    --target "$TARGET" \
    --push \
    --metadata-file "$METADATA_FILE" \
    "$DOCKER_CTX"

ddsign sign "$IMAGE_REF" --docker-metadata-file "$METADATA_FILE"

# Always build the debug version of the Cilium Agent and Operator images
if [[ $IMAGE_NAME == "cilium" || $IMAGE_NAME =~ "cilium-operator" || $IMAGE_NAME =~ "clustermesh-apiserver" ]]; then
    METADATA_FILE_DEBUG=$(mktemp)
    docker buildx build --platform linux/amd64,linux/arm64 \
        --tag "$IMAGE_REF"-debug \
        --file "$DOCKERFILE_PATH" \
        $BUILD_ARGS \
        --label CILIUM_VERSION="$(cat VERSION)" \
        --label target=staging \
        --label CI_PIPELINE_ID="$CI_PIPELINE_ID" \
        --label CI_JOB_ID="$CI_JOB_ID" \
        --label is_fips=true \
        --target debug \
        --push \
        --metadata-file "$METADATA_FILE_DEBUG" \
        "$DOCKER_CTX"
    ddsign sign "$IMAGE_REF"-debug --docker-metadata-file "$METADATA_FILE_DEBUG"
fi
