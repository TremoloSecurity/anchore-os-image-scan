#!/usr/bin/env bash

set -uo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <images.json> <service-account-token-file>" >&2
  exit 2
fi

CONFIG_FILE="$1"
TOKEN_FILE="$2"

for command_name in grype jq curl; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Required command not found: $command_name" >&2
    exit 1
  fi
done

if [[ ! -r "$CONFIG_FILE" ]]; then
  echo "Cannot read configuration file: $CONFIG_FILE" >&2
  exit 1
fi

if [[ ! -r "$TOKEN_FILE" ]]; then
  echo "Cannot read service-account token: $TOKEN_FILE" >&2
  exit 1
fi

if ! jq -e '
  type == "array" and
  all(.[];
    (.image | type == "string" and length > 0) and
    (.url | type == "string" and length > 0)
  )
' "$CONFIG_FILE" >/dev/null; then
  echo "Invalid configuration file" >&2
  exit 1
fi

# Kubernetes service-account token files normally end with a newline.
SERVICE_ACCOUNT_TOKEN="$(tr -d '\r\n' < "$TOKEN_FILE")"

if [[ -z "$SERVICE_ACCOUNT_TOKEN" ]]; then
  echo "Service-account token file is empty" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

overall_status=0
entry_number=0

while IFS= read -r entry; do
  entry_number=$((entry_number + 1))

  image="$(jq -r '.image' <<<"$entry")"
  webhook_url="$(jq -r '.url' <<<"$entry")"

  scan_file="$WORK_DIR/scan-${entry_number}.json"
  vulnerabilities_file="$WORK_DIR/vulnerabilities-${entry_number}.json"
  payload_file="$WORK_DIR/payload-${entry_number}.json"

  echo "Scanning $image for linux/amd64..."

  if ! grype \
      --from registry \
      --platform linux/amd64 \
      --output json \
      "$image" >"$scan_file"; then
    echo "Grype scan failed for $image" >&2
    overall_status=1
    continue
  fi

  # Grype reports OS package types as apk, deb or rpm.
  # Only retain vulnerabilities whose fix state is "fixed" and which
  # provide at least one fixed package version.
  if ! jq '
    [
      .matches[]
      | select(
          (.artifact.type == "apk"
           or .artifact.type == "deb"
           or .artifact.type == "rpm")
          and .vulnerability.fix.state == "fixed"
          and ((.vulnerability.fix.versions // []) | length > 0)
        )
      | {
          package: .artifact.name,
          installedVersion: .artifact.version,
          packageType: .artifact.type,
          vulnerability: .vulnerability.id,
          severity: .vulnerability.severity,
          fixedVersions: .vulnerability.fix.versions
        }
    ]
    | unique_by([
        .package,
        .installedVersion,
        .vulnerability
      ])
  ' "$scan_file" >"$vulnerabilities_file"; then
    echo "Could not parse Grype output for $image" >&2
    overall_status=1
    continue
  fi

  vulnerability_count="$(jq 'length' "$vulnerabilities_file")"

  if [[ "$vulnerability_count" -eq 0 ]]; then
    echo "No fixable OS-package vulnerabilities found in $image"
    continue
  fi

  jq \
    --arg image "$image" \
    --arg platform "linux/amd64" \
    --slurpfile vulnerabilities "$vulnerabilities_file" \
    '{
      image: $image,
      platform: $platform,
      vulnerabilityCount: ($vulnerabilities[0] | length),
      vulnerabilities: $vulnerabilities[0]
    }' >"$payload_file"

  echo "Found $vulnerability_count fixable OS-package vulnerabilities."
  echo "Calling $webhook_url..."

  if ! curl \
      --fail-with-body \
      --silent \
      --show-error \
      --request POST \
      --header "Authorization: Bearer ${SERVICE_ACCOUNT_TOKEN}" \
      --header "Content-Type: application/json" \
      --data-binary "@${payload_file}" \
      "$webhook_url"; then
    echo "Webhook call failed for $image" >&2
    overall_status=1
    continue
  fi

  echo
  echo "Webhook completed successfully for $image"
done < <(jq -c '.[]' "$CONFIG_FILE")

exit "$overall_status"