#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 || $# -gt 5 ]]; then
  echo "Usage: $0 EXPECTED_AWS_ACCOUNT_ID REGION AVAILABILITY_ZONE INSTANCE_NAME [SNAPSHOT_UTC_HOUR]" >&2
  exit 2
fi

expected_account_id="$1"
region="$2"
availability_zone="$3"
instance_name="$4"
snapshot_hour="${5:-08:00}"
static_ip_name="${instance_name}-ip"

actual_account_id="$(aws sts get-caller-identity --query Account --output text)"
if [[ "$actual_account_id" != "$expected_account_id" ]]; then
  echo "Refusing provisioning: authenticated AWS account is $actual_account_id, expected $expected_account_id" >&2
  exit 1
fi

if aws lightsail get-instance --region "$region" --instance-name "$instance_name" >/dev/null 2>&1; then
  echo "Refusing provisioning: instance already exists: $instance_name" >&2
  exit 1
fi

aws lightsail create-instances \
  --region "$region" \
  --availability-zone "$availability_zone" \
  --instance-names "$instance_name" \
  --blueprint-id ubuntu_24_04 \
  --bundle-id nano_3_0 \
  --add-ons "addOnType=AutoSnapshot,autoSnapshotAddOnRequest={snapshotTimeOfDay=$snapshot_hour}" >/dev/null

for _attempt in {1..36}; do
  state="$(aws lightsail get-instance \
    --region "$region" \
    --instance-name "$instance_name" \
    --query 'instance.state.name' \
    --output text)"
  if [[ "$state" == "running" ]]; then
    break
  fi
  sleep 5
done

if [[ "${state:-}" != "running" ]]; then
  echo "Instance did not reach running state: ${state:-unknown}" >&2
  exit 1
fi
aws lightsail allocate-static-ip --region "$region" --static-ip-name "$static_ip_name" >/dev/null
aws lightsail attach-static-ip --region "$region" --static-ip-name "$static_ip_name" --instance-name "$instance_name" >/dev/null
aws lightsail open-instance-public-ports \
  --region "$region" \
  --instance-name "$instance_name" \
  --port-info fromPort=443,toPort=443,protocol=tcp >/dev/null

aws lightsail get-instance \
  --region "$region" \
  --instance-name "$instance_name" \
  --query 'instance.{Name:name,State:state.name,PublicIP:publicIpAddress,Bundle:bundleId,Blueprint:blueprintId,Region:location.regionName,Zone:location.availabilityZone}' \
  --output json
