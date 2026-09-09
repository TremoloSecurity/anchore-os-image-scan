#!/usr/bin/env bash

set -uo pipefail

###############################################################################
# Usage
###############################################################################

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <images.json> <service-account-token-file>" >&2
  exit 2
fi

CONFIG_FILE="$1"
TOKEN_FILE="$2"

###############################################################################
# Dependencies and input validation
###############################################################################

for required_command in grype jq curl; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    echo "Required command not found: $required_command" >&2
    exit 1
  fi
done

if [[ ! -r "$CONFIG_FILE" ]]; then
  echo "Cannot read configuration file: $CONFIG_FILE" >&2
  exit 1
fi

if [[ ! -r "$TOKEN_FILE" ]]; then
  echo "Cannot read service-account token file: $TOKEN_FILE" >&2
  exit 1
fi

if ! jq -e '
  type == "array"
  and all(.[];
    (.image | type == "string" and length > 0)
    and
    (.url | type == "string" and length > 0)
  )
' "$CONFIG_FILE" >/dev/null; then
  echo "Invalid configuration file: $CONFIG_FILE" >&2
  echo "Expected an array containing objects with image and url strings." >&2
  exit 1
fi

SERVICE_ACCOUNT_TOKEN="$(tr -d '\r\n' <"$TOKEN_FILE")"

if [[ -z "$SERVICE_ACCOUNT_TOKEN" ]]; then
  echo "Service-account token file is empty: $TOKEN_FILE" >&2
  exit 1
fi

###############################################################################
# Temporary files
###############################################################################

WORK_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$WORK_DIR"
}

trap cleanup EXIT INT TERM

###############################################################################
# Scan configuration
###############################################################################

total_entries="$(jq 'length' "$CONFIG_FILE")"
entry_number=0
scan_failures=0
webhook_failures=0
notifications_sent=0
images_without_fixes=0

echo "Found $total_entries image configuration(s)."
echo

###############################################################################
# Process each entry
#
# File descriptor 3 is used intentionally. This prevents grype or curl from
# consuming the remaining JSON entries through standard input.
###############################################################################

while IFS= read -r entry <&3; do
  entry_number=$((entry_number + 1))

  image="$(jq -r '.image' <<<"$entry")"
  webhook_url="$(jq -r '.url' <<<"$entry")"

  scan_file="$WORK_DIR/scan-${entry_number}.json"
  vulnerabilities_file="$WORK_DIR/vulnerabilities-${entry_number}.json"
  payload_file="$WORK_DIR/payload-${entry_number}.json"

  echo "[$entry_number/$total_entries] Scanning: $image"
  echo "Platform: linux/amd64"

  if ! grype \
      --from registry \
      --platform linux/amd64 \
      --output json \
      "$image" \
      </dev/null >"$scan_file"; then
    echo "ERROR: Grype scan failed for $image" >&2
    scan_failures=$((scan_failures + 1))
    echo
    continue
  fi

  # Retain only operating-system packages for which Grype reports at least
  # one fixed version.
  if ! jq '
    [
      (.matches // [])[]
      | select(
          (
            .artifact.type == "apk"
            or .artifact.type == "deb"
            or .artifact.type == "rpm"
            or .artifact.type == "alpm"
            or .artifact.type == "portage"
          )
          and
          (.vulnerability.fix.state == "fixed")
          and
          (((.vulnerability.fix.versions // []) | length) > 0)
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
    echo "ERROR: Could not parse Grype output for $image" >&2
    scan_failures=$((scan_failures + 1))
    echo
    continue
  fi

  vulnerability_count="$(jq 'length' "$vulnerabilities_file")"

  if [[ "$vulnerability_count" -eq 0 ]]; then
    echo "No fixable OS-package vulnerabilities found."
    images_without_fixes=$((images_without_fixes + 1))
    echo
    continue
  fi

  echo "Found $vulnerability_count fixable OS-package vulnerability record(s)."

  if ! jq \
      --null-input \
      --arg image "$image" \
      --arg platform "linux/amd64" \
      --argjson vulnerabilityCount "$vulnerability_count" \
      --slurpfile vulnerabilities "$vulnerabilities_file" \
      '{
        image: $image,
        platform: $platform,
        vulnerabilityCount: $vulnerabilityCount,
        vulnerabilities: $vulnerabilities[0]
      }' >"$payload_file"; then
    echo "ERROR: Could not create webhook payload for $image" >&2
    webhook_failures=$((webhook_failures + 1))
    echo
    continue
  fi

  echo "Calling webhook: $webhook_url"

  if ! curl \
      --fail-with-body \
      --silent \
      --show-error \
      --request POST \
      --header "Authorization: Bearer $SERVICE_ACCOUNT_TOKEN" \
      --header "Content-Type: application/json" \
      --data-binary "@$payload_file" \
      "$webhook_url" \
      </dev/null; then
    echo >&2
    echo "ERROR: Webhook request failed for $image" >&2
    webhook_failures=$((webhook_failures + 1))
    echo
    continue
  fi

  notifications_sent=$((notifications_sent + 1))

  echo
  echo "Webhook completed successfully."
  echo

done 3< <(jq -c '.[]' "$CONFIG_FILE")

###############################################################################
# Summary
###############################################################################

echo "Scan complete."
echo "  Images configured:       $total_entries"
echo "  Notifications sent:      $notifications_sent"
echo "  Images without fixes:    $images_without_fixes"
echo "  Scan failures:           $scan_failures"
echo "  Webhook failures:        $webhook_failures"

if [[ "$scan_failures" -gt 0 || "$webhook_failures" -gt 0 ]]; then
  exit 1
fi

exit 0