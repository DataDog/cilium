#!/usr/bin/env bash
set -exuo pipefail

# Find the 3 latest -dd tags on the current branch
GIT_TAGS_TO_BUILD=$(git --no-pager tag --sort=-creatordate --merged HEAD --list \*-dd\* | head -n 3)
GIT_TAGS_TO_BUILD="1.15.10-dd4-anton-test-build-3"

# Trigger a CI pipeline for each tag
for TAG in $GIT_TAGS_TO_BUILD; do
  curl --request POST \
       --form token="${CI_JOB_TOKEN}" \
       --form ref="$TAG" \
       "https://gitlab.ddbuild.io/api/v4/projects/${CI_PROJECT_ID}/trigger/pipeline"
done
