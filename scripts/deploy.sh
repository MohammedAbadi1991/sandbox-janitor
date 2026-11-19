#!/usr/bin/env bash
# Deploys the Sandbox Janitor stack. Usage: scripts/deploy.sh [extra parameter overrides]
#   REDTEAM=1 scripts/deploy.sh      also deploys the red-team role and probe for the caller
set -euo pipefail
cd "$(dirname "$0")/.."
REGION="${AWS_REGION:-us-east-1}"
STACK="${STACK_NAME:-sandbox-janitor}"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
BUCKET="${ARTIFACT_BUCKET:-sandbox-janitor-artifacts-$ACCOUNT-$REGION}"
aws s3api head-bucket --bucket "$BUCKET" 2>/dev/null || aws s3 mb "s3://$BUCKET" --region "$REGION" >/dev/null
PARAMS=("$@")
if [ "${REDTEAM:-0}" = "1" ]; then
  PARAMS+=("RedTeamPrincipalArn=$(aws sts get-caller-identity --query Arn --output text)")
fi
aws cloudformation package --template-file template.yaml --s3-bucket "$BUCKET" --output-template-file .packaged.yaml --region "$REGION" >/dev/null
OVERRIDES=(); [ ${#PARAMS[@]} -gt 0 ] && OVERRIDES=(--parameter-overrides "${PARAMS[@]}")
aws cloudformation deploy --template-file .packaged.yaml --stack-name "$STACK" --region "$REGION" \
  --capabilities CAPABILITY_NAMED_IAM "${OVERRIDES[@]}"
aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" \
  --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' --output text
