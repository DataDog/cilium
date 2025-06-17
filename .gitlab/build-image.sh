#!/usr/bin/env bash
set -exuo pipefail

TARGET="${TARGET:-}"

# Replicate images
IFS=$'\n'
for arg_name in ${IMAGES_TO_MIRROR:-}; do
    source_image_ref=$(grep "ARG ${arg_name}=" $DOCKERFILE_PATH | sed 's/^[^=]*=//')
    dest_image_ref="registry.ddbuild.io/images/mirror"$(echo $source_image_ref | sed 's|^[^/]*||')
    if ! crane manifest $dest_image_ref; then
        echo "Mirroring $source_image_ref to $dest_image_ref"
        crane copy $source_image_ref $dest_image_ref
    fi
    DOCKER_BUILD_ARGS+=$'\n'"${arg_name}=${dest_image_ref}"
done
IFS=$' '

# Construct valid --build-args arguments from the DOCKER_BUILD_ARGS variable
BUILD_ARGS="--build-arg MODIFIERS=BORINGCRYPTO=1"
IFS=$'\n'
for arg in ${DOCKER_BUILD_ARGS:-}; do
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
    --metadata-file "$METADATA_FILE" \
    --output type=image,push=true,compression=zstd,force-compression=true,oci-mediatypes=true \
    "$DOCKER_CTX"

ddsign sign "$IMAGE_REF" --docker-metadata-file "$METADATA_FILE"

# Always build the debug version of the Cilium Agent and Operator images
if [[ $IMAGE_NAME == "cilium" || $IMAGE_NAME =~ "cilium-operator" ]]; then
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
        --metadata-file "$METADATA_FILE_DEBUG" \
        --output type=image,push=true,compression=zstd,force-compression=true,oci-mediatypes=true \
        "$DOCKER_CTX"
    ddsign sign "$IMAGE_REF"-debug --docker-metadata-file "$METADATA_FILE_DEBUG"
fi
