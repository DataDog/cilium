#!/usr/bin/env bash
set -exuo pipefail

# This is required for the set-head command to succeed
git config --global --add safe.directory $CI_PROJECT_DIR
# Set the branch where .campaigns.toml is located
git remote set-head origin $CI_COMMIT_REF_NAME

export CURRENT_DATE=$(date +"%Y-%m-%d")
envsubst < .gitlab/campaign-template.yaml > campaign.yaml
cat campaign.yaml
campaigns start --env prod --config-file campaign.yaml
