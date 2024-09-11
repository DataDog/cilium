#!/usr/bin/env bash
set -exuo pipefail

# This is required for the set-head command to succeed
git config --global --add safe.directory $CI_PROJECT_DIR
# Set the branch where .campaigns.toml is located
git remote set-head origin $CI_COMMIT_REF_NAME

export CURRENT_DATE=$(date +"%Y-%m-%d")
envsubst < .gitlab/campaign-template.yaml > campaign.yaml

# Generate search and replace rules for image tags
# This will bump only existing image tags
while IFS=' ' read -r GIT_TAG IMAGE_TAG; do
  cat <<EOF >> campaign.yaml
  - op: "custom/search_and_replace"
    key: !perl/regexp "\"${GIT_TAG}[a-z0-9-]*\".*since.*"
    value: "\"${IMAGE_TAG}\" # since ${CURRENT_DATE}"
EOF
done < image_tags.txt

campaigns start --env prod --config-file campaign.yaml
