#!/usr/bin/env bash
# Fails when a tracked file looks like proprietary model signature or
# calibration data. This repository is public, so such files must never be
# committed. See CONTRIBUTING.md ("Proprietary artifacts").
set -euo pipefail

# Files that legitimately mention the patterns below (this guard and its docs).
EXCLUDES=(
  ':(exclude)scripts/check_proprietary_artifacts.sh'
  ':(exclude).github/workflows/artifact-guard.yml'
  ':(exclude)CONTRIBUTING.md'
)

status=0

# Forbidden filenames.
while IFS= read -r path; do
  echo "::error file=${path}::Proprietary artifact filename is tracked: ${path}"
  status=1
done < <(git ls-files -- . "${EXCLUDES[@]}" | grep -E '(\.signature\.json|(^|/)calibration\.json)$' || true)

# Forbidden content. No -I flag, so binary files (e.g. .db) are searched too.
while IFS= read -r path; do
  echo "::error file=${path}::Tracked file contains proprietary calibration marker: ${path}"
  status=1
done < <(git grep -lE 'std_curve|lep_curve' -- . "${EXCLUDES[@]}" || true)

if [ "$status" -ne 0 ]; then
  echo "Proprietary artifact guard failed. Remove the files above; see CONTRIBUTING.md."
else
  echo "Proprietary artifact guard passed."
fi
exit "$status"
