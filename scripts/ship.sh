#!/usr/bin/env bash
# Send your work to develop in one command:
#   bash scripts/ship.sh "feat(ioc): what you did"
# It commits everything, pushes, opens a pull request, and sets it to merge by itself once CI passes.
# If it stops on an error, fix what it says and run the exact same command again.
set -euo pipefail
msg=${1:?'usage: bash scripts/ship.sh "feat(ioc): what you did"'}

branch=$(git branch --show-current)
case "$branch" in
  develop | QA | main)
    branch="work/$(gh api user -q .login)-$(date +%Y%m%d-%H%M%S)"
    git switch -c "$branch"
    ;;
esac

git add -A
if ! git diff --cached --quiet; then
  git commit -m "$msg"
fi
git push -u origin "$branch"

if ! gh pr view "$branch" --json number >/dev/null 2>&1; then
  gh pr create --base develop --head "$branch" --title "$msg" --body "Opened with scripts/ship.sh"
fi
gh pr merge "$branch" --auto --merge

echo
echo "Done. It merges into develop by itself when CI is green:"
gh pr view "$branch" --json url -q .url
echo "Start your next task with: git switch develop && git pull"
