#!/usr/bin/env bash
# merge-back-report — the git-branching skill's merge-back report (techspec
# skills/git-branching/SKILL.md, §5 Hotfix, step 6). Lists the commits on release/<track>-X.Y.Z
# branches that are not on main, and with --max-age-days fails when one has waited longer than
# that: a hotfix that is never merged back is lost from the next release.
#
# No network, no state; safe to re-run. Exit 0 = report printed (and nothing overdue),
# 1 = something overdue or bad input, 2 = usage.
#
#   merge-back-report.sh [--remote <name>] [--main <branch>] [--track <track>]
#                        [--max-age-days <N>] [--now <unix-seconds>]
#
#   --remote        whose branches to read (default origin): refs/remotes/<remote>/release/* and
#                   refs/remotes/<remote>/<main>. Fetch them first (ci/merge-back-check.yml does).
#   --main          the base branch (default $BRANCH_CHECK_BASE, else main: check.sh's setting).
#   --track         only release/<track>-X.Y.Z.
#   --max-age-days  exit 1 when a commit has been on its release branch, not on main, for more
#                   than N days (ci/merge-back-check.yml passes MERGE_BACK_DAYS).
#   --now           the time to measure from (tests; default: now).
#
# A commit counts as on main when main has it, or has a commit with the same `git patch-id`
# (cherry-picked, or rebase-merged). A squash of several release commits into one main commit
# matches none of them: merge the merge-back PR with a merge commit (or rebase), not a squash.
# Merge commits on the release branch are not listed (the commits they bring in are).
# A commit's age runs from when it reached the release branch: the committer time of the first
# commit on the branch's first-parent line that contains it (the hotfix PR's merge).
#
# Output, one line per commit (tab-separated), oldest branch first:
#   <release-branch> <sha> <reached-branch, UTC> <age>d <subject>
# then "merge-back-report: <n> commit(s) on <k> release branch(es) not on <main>".
# A release tag <track>-vX.Y.Z whose commit is on no release branch and not on main (its branch
# was deleted before the merge-back) is listed too, labelled tag:<tag>, with a warning.
# A ref under release/ that is not release/<track>-X.Y.Z is skipped with a warning (its name is
# printed escaped; git allows $(...), `...` and ; in branch names).
set -euo pipefail

usage() { sed -n '2,34p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

# The same names as check.sh (merge-back-report.test.sh keeps the two in step).
VER='[0-9]+\.[0-9]+\.[0-9]+'
ID='[a-z][a-z0-9.-]*'

die() { echo "merge-back-report: FAIL: $*" >&2; exit 1; }

remote=origin main=${BRANCH_CHECK_BASE:-main} track="" maxdays="" now=""
while (($#)); do
  case $1 in
    --remote) [[ $# -ge 2 ]] || usage; remote=$2; shift 2 ;;
    --main) [[ $# -ge 2 ]] || usage; main=$2; shift 2 ;;
    --track) [[ $# -ge 2 ]] || usage; track=$2; shift 2 ;;
    --max-age-days) [[ $# -ge 2 ]] || usage; maxdays=$2; shift 2 ;;
    --now) [[ $# -ge 2 ]] || usage; now=$2; shift 2 ;;
    *) usage ;;
  esac
done

[[ $remote =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*$ && $remote != *..* ]] || die "'$(printf '%q' "$remote")' is not a remote name"
[[ $main =~ ^[A-Za-z0-9_][A-Za-z0-9._/-]*$ && $main != *..* && $main != */ ]] || die "'$(printf '%q' "$main")' is not a branch name"
[[ -z $track || $track =~ ^$ID$ ]] || die "'$(printf '%q' "$track")' is not a track name"
[[ -z $maxdays || $maxdays =~ ^[0-9]{1,4}$ ]] || die "--max-age-days '$(printf '%q' "$maxdays")' is not a number of days"
[[ -z $now || $now =~ ^[0-9]{1,12}$ ]] || die "--now '$(printf '%q' "$now")' is not unix seconds"
[[ -n $now ]] || now=$(date +%s)

mainref="refs/remotes/$remote/$main"
git rev-parse --verify --quiet "$mainref^{commit}" >/dev/null || die "$remote/$main is not in this clone (fetch it)"

reached() { # reached <commit> <ref> <first-parent list>: unix time the commit reached the ref's first-parent line
  # No `grep -q` here: under pipefail its early exit kills the producer with SIGPIPE on a long
  # history and the test reads as false (review of 0.4.0, round 1). The list is read in full.
  local c=$1 ref=$2 fp=$3 first
  if grep -x -- "$c" <<<"$fp" >/dev/null; then first=$c
  else
    first=$(git rev-list --first-parent --reverse --ancestry-path "$c..$ref")
    first=${first%%$'\n'*}
  fi
  git show -s --format=%ct "${first:-$c}"
}

total=0 branches=0 overdue=0
rows=() relrefs=()
report() { # report <label> <ref>: list the commits on <ref> not on main
  local label=$1 ref=$2 commits fp c t age when subj flag
  commits=$(git rev-list --no-merges --right-only --cherry-pick --reverse "$mainref...$ref")
  [[ -n $commits ]] || return 0
  fp=$(git rev-list --first-parent "$ref")
  branches=$((branches + 1))
  while IFS= read -r c; do
    t=$(reached "$c" "$ref" "$fp")
    age=$(((now - t) / 86400))
    when=$(date -u -d "@$t" '+%Y-%m-%d %H:%M' 2>/dev/null || date -u -r "$t" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "@$t")
    subj=$(git show -s --format=%s "$c" | LC_ALL=C tr -d '\000-\037\177')
    flag=""
    if [[ -n $maxdays ]] && ((now - t > maxdays * 86400)); then flag=" OVERDUE"; overdue=$((overdue + 1)); fi
    rows+=("$t"$'\t'"$label"$'\t'"$c"$'\t'"$when UTC"$'\t'"${age}d$flag"$'\t'"$subj")
    total=$((total + 1))
  done <<<"$commits"
}

while IFS= read -r ref; do
  name=${ref#"refs/remotes/$remote/"}
  if [[ ! $name =~ ^release/($ID)-($VER)$ || $name == *..* ]]; then
    echo "merge-back-report: WARN: $(printf '%q' "$remote/$name") is not release/<track>-X.Y.Z; skipped" >&2
    continue
  fi
  relrefs+=("$ref")
  if [[ -n $track && $name != "release/$track-"* ]]; then continue; fi
  if [[ -n $track && ! ${name#"release/$track-"} =~ ^$VER$ ]]; then continue; fi
  report "$name" "$ref"
done < <(git for-each-ref --format='%(refname)' "refs/remotes/$remote/release/")

# Backstop for a deleted release branch: a release tag <track>-vX.Y.Z (the clone's tags; the
# overdue job fetches them) whose commit is neither on main nor on any release branch above.
while IFS= read -r tg; do
  [[ $tg =~ ^($ID)-v($VER)$ && $tg != *..* ]] || continue
  [[ -z $track || ${BASH_REMATCH[1]} == "$track" ]] || continue
  tc=$(git rev-parse --verify --quiet "refs/tags/$tg^{commit}") || continue
  git merge-base --is-ancestor "$tc" "$mainref" && continue
  covered=0
  for r in ${relrefs[@]+"${relrefs[@]}"}; do
    if git merge-base --is-ancestor "$tc" "$r"; then covered=1; break; fi
  done
  ((covered)) && continue
  echo "merge-back-report: WARN: release tag $tg is on no release branch and not on $main (was its release branch deleted?)" >&2
  report "tag:$tg" "refs/tags/$tg"
done < <(git for-each-ref --format='%(refname:strip=2)' refs/tags/)

if ((${#rows[@]})); then
  printf '%s\n' "${rows[@]}" | sort -t $'\t' -s -k1,1n | cut -f2-
fi
echo "merge-back-report: $total commit(s) on $branches release branch(es) or tag(s) not on $main" >&2
if ((overdue > 0)); then
  echo "merge-back-report: FAIL: $overdue commit(s) not merged back to $main within $maxdays day(s); open the merge-back PR (SKILL.md §5 Hotfix, step 6)" >&2
  exit 1
fi
