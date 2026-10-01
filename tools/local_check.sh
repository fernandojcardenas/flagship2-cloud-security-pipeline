#!/usr/bin/env bash
# Apply terraform/baseline to a local Moto server and run the posture checks.
# No AWS account or credentials involved: everything runs on this machine.
#
#   pip install -r tools/requirements.txt
#   tools/local_check.sh
#
# Works on a scratch copy of terraform/baseline, so it never touches any
# state file in the real directory.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
moto_pid=""
cleanup() {
  [ -n "$moto_pid" ] && kill "$moto_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

if curl -s -o /dev/null http://localhost:5000/moto-api/; then
  echo "Using the Moto server already running on port 5000."
  echo "(Results assume it holds nothing but this project; restart it if unsure.)"
else
  moto_server -p 5000 >"$work/moto.log" 2>&1 &
  moto_pid=$!
  for _ in $(seq 1 30); do
    curl -s -o /dev/null http://localhost:5000/moto-api/ && break
    sleep 1
  done
fi

cp -R "$repo/terraform/baseline/." "$work/tf"
rm -rf "$work/tf/.terraform" "$work/tf"/terraform.tfstate*
cp "$repo/emulator/provider_override.tf" "$work/tf/"

export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
terraform -chdir="$work/tf" init -input=false -no-color >/dev/null
terraform -chdir="$work/tf" apply -auto-approve -input=false -no-color | grep -E "^Apply complete"

python3 "$repo/tools/posture_check.py"
