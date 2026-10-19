#!/usr/bin/env bash
# Recall against Trail of Bits' overtly-malicious-skills (four skills built to defeat
# skill scanners). The corpus is fetched at run time, NOT vendored: it declares no
# license. Nothing in it is executed; the screen only reads files.
#
# Pinned to the commit the README's numbers were measured at. Override with
# TOB_REF=<commit> (or TOB_REF=HEAD) to measure a newer corpus.
#
# Lanes: the full lane (--provenance untrusted-web) and the skill lane
# (--provenance claude-surface, what the claude-code preset uses). At the pinned
# commit the full lane flags 4 of 4 and the skill lane 3 of 4; see
# docs/measured-recall.md, including why this corpus is a regression check now.
set -euo pipefail
ref="${TOB_REF:-4ffbf9461ef0505f9ce76a0d3694a18ec33ea531}"
dir="$(mktemp -d)"
trap 'rm -rf -- "$dir"' EXIT
git clone -q https://github.com/trailofbits/overtly-malicious-skills "$dir/tob"
git -C "$dir/tob" checkout -q "$ref"
echo "corpus: $(git -C "$dir/tob" log -1 --format='%H %ad' --date=short)"
for skill in "$dir"/tob/skills/*/; do
    name="$(basename "$skill")"
    for lane in untrusted-web claude-surface; do
        rc=0
        injection-screen "$skill" --provenance "$lane" --no-session >/dev/null 2>&1 || rc=$?
        case "$rc" in
            0) verdict="missed" ;;
            1) verdict="FLAGGED" ;;
            2) verdict="not evaluable (exit 2)" ;;
            3) verdict="partial, no findings (exit 3)" ;;
            *) verdict="error (exit $rc)" ;;
        esac
        printf '%-18s %-15s %s\n' "$name" "$lane" "$verdict"
    done
done
