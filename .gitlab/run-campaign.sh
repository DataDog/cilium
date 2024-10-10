#!/usr/bin/env bash
set -exuo pipefail

# This is required for the set-head command to succeed
git config --global --add safe.directory "$CI_PROJECT_DIR"
# Set the branch where .campaigns.toml is located
BRANCH=$(git branch --all --contains "$CI_COMMIT_TAG" --format='%(refname:short)' | sed -n 's/^origin\///p')
git remote set-head origin "$BRANCH"

export CURRENT_DATE=$(date +"%Y-%m-%d")
export IMAGE_TAG="$CI_COMMIT_TAG"
TIMESTAMP=${CI_PIPELINE_CREATED_AT//:/-}
TIMESTAMP=${TIMESTAMP,,}
IMAGE_TAG="${IMAGE_TAG}-${TIMESTAMP}"
envsubst < .gitlab/campaign-template.yaml > campaign.yaml
cat campaign.yaml

campaigns start --env prod --config-file campaign.yaml
