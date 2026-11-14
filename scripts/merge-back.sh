#!/usr/bin/env bash
# merge-back — the git-branching skill's merge-back check (techspec skills/git-branching/SKILL.md,
# "The three loops", Run). A hotfix reaches a release branch by one PR and main by a second PR
# carrying the same patch; this compares the two by `git patch-id --stable` (whitespace and line
# numbers ignored, so a cherry-pick onto main matches).
#
# No network, no state; safe to re-run. Exit 0 = found / printed, 1 = not found or bad input, 2 = usage.
#
#   merge-back.sh patch-id <base-sha> <head-sha>
#       print the patch-id of the PR diff <base>...<head> (from their merge base to <head>)
#   merge-back.sh find <base-sha> <head-sha> <candidates-file>
#       <base>/<head>: the hotfix PR. <candidates-file>: one PR into main per line,
#       "<number> <open|merged> <base-sha> <head-sha>" (ci/merge-back-check.yml writes it from the
#       GitHub API). Prints "#<number> <state>" for every PR whose patch-id equals the hotfix's,
#       then "patch-id <id>". Exit 0 if at least one matches, 1 if none does.
#   merge-back.sh check-values <base-sha> <head-sha> <base-ref> <named>
#       refuse (exit 1) unless the values ci/merge-back-check.yml read from the GitHub API are
#       what they claim: two commit shas, a base ref release/<track>-X.Y.Z (check.sh's names), and
#       a Merge-back: result that is empty, "#<n> open", "#<n> merged" or "-#<n>". The values are
#       data: the workflow never sources or evals them, and refuses before using them otherwise
#       (git allows $(...), `...` and ; in branch names).
#
# The commits named must already be in the clone (the workflow fetches refs/pull/<n>/head).
set -euo pipefail

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

# The same names as check.sh (merge-back.test.sh keeps the two in step).
VER='[0-9]+\.[0-9]+\.[0-9]+'
ID='[a-z][a-z0-9.-]*'

pid() { # pid <base> <head>: patch-id of base...head, empty if the diff is empty
  git diff --no-color --no-ext-diff "$1...$2" | git patch-id --stable | cut -d' ' -f1
}

have() { git cat-file -e "$1^{commit}" 2>/dev/null; }

case ${1:-} in
  patch-id)
    [[ $# == 3 ]] || usage
    if ! { have "$2" && have "$3"; }; then echo "merge-back: FAIL: commit not in this clone" >&2; exit 1; fi
    p=$(pid "$2" "$3")
    [[ -n $p ]] || { echo "merge-back: FAIL: $2...$3 is an empty diff" >&2; exit 1; }
    echo "$p" ;;
  find)
    [[ $# == 4 ]] || usage
    if ! { have "$2" && have "$3"; }; then echo "merge-back: FAIL: hotfix commit not in this clone" >&2; exit 1; fi
    want=$(pid "$2" "$3")
    [[ -n $want ]] || { echo "merge-back: FAIL: the hotfix PR $2...$3 is an empty diff" >&2; exit 1; }
    found=0
    while read -r n state b h _; do
      [[ -z ${n:-} || $n == \#* ]] && continue
      case $state in open|merged) ;; *) continue ;; esac
      if ! have "$b" || ! have "$h"; then
        echo "merge-back: WARN: #$n: commits not in this clone, skipped" >&2; continue
      fi
      [[ $(pid "$b" "$h") == "$want" ]] && { echo "#$n $state"; found=1; }
    done <"$4"
    echo "patch-id $want"
    ((found)) ;;
  check-values)
    [[ $# == 5 ]] || usage
    bad() { echo "merge-back: FAIL: $1; refusing" >&2; exit 1; }
    sha='^([0-9a-f]{40}|[0-9a-f]{64})$'
    [[ $2 =~ $sha ]] || bad "base sha '$2' is not a commit sha"
    [[ $3 =~ $sha ]] || bad "head sha '$3' is not a commit sha"
    [[ $4 =~ ^release/($ID)-($VER)$ && $4 != *..* ]] || bad "base ref '$4' is not release/<track>-X.Y.Z"
    [[ -z $5 || $5 =~ ^#[0-9]+\ (open|merged)$ || $5 =~ ^-#[0-9]+$ ]] || bad "Merge-back result '$5' is not '#<n> open|merged' or '-#<n>'"
    ;;
  *) usage ;;
esac
