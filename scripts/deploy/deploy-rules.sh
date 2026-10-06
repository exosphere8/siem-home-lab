#!/usr/bin/env bash
# Deploy this repository's Wazuh rules to the manager, safely.
#
#   sudo bash scripts/deploy/deploy-rules.sh            # deploy, test, restart
#   sudo bash scripts/deploy/deploy-rules.sh --dry-run  # show what would change
#
# Steps: back up the current custom rules, copy detections/**/*.xml into
# /var/ossec/etc/rules/, check the whole configuration with `wazuh-analysisd -t`, and only
# then restart the manager. If the check fails, the backup is restored and nothing restarts,
# so a broken rule can never take the manager down.
set -euo pipefail

OSSEC_DIR="${OSSEC_DIR:-/var/ossec}"
RULES_DIR="$OSSEC_DIR/etc/rules"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DRY_RUN=false

usage() {
    sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
}

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        -h | --help) usage; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; usage >&2; exit 2 ;;
    esac
done

mapfile -t RULE_FILES < <(find "$REPO_ROOT/detections" -name '*.xml' -type f | sort)
if [[ ${#RULE_FILES[@]} -eq 0 ]]; then
    echo "no rule files found under $REPO_ROOT/detections" >&2
    exit 1
fi

if $DRY_RUN; then
    echo "Would install ${#RULE_FILES[@]} rule file(s) into $RULES_DIR:"
    printf '  %s\n' "${RULE_FILES[@]#"$REPO_ROOT"/}"
    exit 0
fi

if [[ $EUID -ne 0 ]]; then
    echo "run as root (sudo): the rules directory is owned by root:wazuh" >&2
    exit 1
fi
if [[ ! -x "$OSSEC_DIR/bin/wazuh-analysisd" ]]; then
    echo "$OSSEC_DIR/bin/wazuh-analysisd not found: is this the Wazuh manager?" >&2
    exit 1
fi

BACKUP="$(mktemp -d /tmp/wazuh-rules-backup.XXXXXX)"
cp -a "$RULES_DIR/." "$BACKUP/"
echo "Backed up $RULES_DIR to $BACKUP"

restore() {
    echo "Configuration test failed: restoring the previous rules." >&2
    rm -f "$RULES_DIR"/1[0-1][0-9][0-9][0-9][0-9]-*.xml
    cp -a "$BACKUP/." "$RULES_DIR/"
}

for file in "${RULE_FILES[@]}"; do
    install -o root -g wazuh -m 0660 "$file" "$RULES_DIR/$(basename "$file")"
    echo "  installed $(basename "$file")"
done

if ! "$OSSEC_DIR/bin/wazuh-analysisd" -t; then
    restore
    exit 1
fi

systemctl restart wazuh-manager
systemctl is-active --quiet wazuh-manager
echo "Deployed ${#RULE_FILES[@]} rule file(s); wazuh-manager restarted and running."
echo "Test individual events with: $OSSEC_DIR/bin/wazuh-logtest"
