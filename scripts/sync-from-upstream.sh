#!/usr/bin/env bash
# Mirrors the observer/ directory of Phigon's main repository into this one.
#
# Run from the root of a checkout of this repository, with the upstream
# repository checked out (full history) in ./.upstream. For every upstream
# commit on the first-parent line that changed observer/, it creates one commit
# here with the same tree, title, author, and date, plus an
# "Upstream-Commit: <sha>" trailer that records where it came from. Upstream
# tags named observer-vX.Y.Z become vX.Y.Z here once their tree is mirrored.
#
# Environment:
#   AUTHOR_EMAIL_MAP  optional lines of "upstream@email=public@email"
#   UPSTREAM_BRANCH   upstream branch to follow (default: imp)
set -euo pipefail

upstream=.upstream
prefix=observer
branch=${UPSTREAM_BRANCH:-imp}
head=$(git -C "$upstream" rev-parse "origin/$branch")

last=$(git log --format=%B -n 500 | sed -n 's/^Upstream-Commit: \([0-9a-f]\{40\}\)$/\1/p' | head -n 1)
if [ -z "$last" ]; then
  echo "No Upstream-Commit trailer found; import the first commit by hand." >&2
  exit 1
fi
if ! git -C "$upstream" merge-base --is-ancestor "$last" "$head"; then
  echo "Last mirrored commit $last is not on upstream $branch; refusing to continue." >&2
  exit 1
fi

map_email() {
  local email=$1 from to
  while IFS='=' read -r from to; do
    if [ -n "$from" ] && [ "$email" = "$from" ]; then
      printf '%s' "$to"
      return
    fi
  done <<<"${AUTHOR_EMAIL_MAP:-}"
  printf '%s' "$email"
}

# Applies the same mapping to text, such as Signed-off-by lines in a message.
map_text() {
  local text=$1 from to
  while IFS='=' read -r from to; do
    if [ -n "$from" ]; then
      text=${text//"$from"/"$to"}
    fi
  done <<<"${AUTHOR_EMAIL_MAP:-}"
  printf '%s' "$text"
}

merge_pattern='^Merge pull request #[0-9]+ from '
mirrored=0
for commit in $(git -C "$upstream" rev-list --reverse --first-parent "$last..$head"); do
  if git -C "$upstream" diff --quiet "$commit^1" "$commit" -- "$prefix"; then
    continue
  fi

  # Replace the whole tree with upstream's observer/ at this commit.
  git rm -rq --ignore-unmatch -- . >/dev/null
  git -C "$upstream" archive --format=tar "$commit" "$prefix" | tar -x --strip-components=1 -f -
  git add -A
  # Copy executable bits from upstream exactly; not every platform keeps them.
  for mode in 100755 100644; do
    flag=$([ "$mode" = 100755 ] && echo +x || echo -x)
    git -C "$upstream" ls-tree -r "$commit" -- "$prefix" |
      awk -v mode="$mode" -v prefix="$prefix/" -F '	' '{ split($1, meta, " "); if (meta[1] == mode) { path = $2; sub("^" prefix, "", path); printf "%s%c", path, 0 } }' |
      xargs -0 -r git update-index --chmod="$flag" --
  done
  if git diff --cached --quiet; then
    continue
  fi

  subject=$(git -C "$upstream" log -1 --format=%s "$commit")
  body=$(git -C "$upstream" log -1 --format=%b "$commit")
  if [[ $subject =~ $merge_pattern ]]; then
    # A merged pull request: use its title and keep private branch names out.
    subject=$(printf '%s\n' "$body" | sed -n '/[^[:space:]]/{p;q;}')
    body=""
  fi
  [ -n "$subject" ] || subject="Update the observer"
  subject=$(map_text "$subject")
  body=$(map_text "$body")

  message=$(mktemp)
  {
    printf '%s\n\n' "$subject"
    if [ -n "$body" ]; then printf '%s\n\n' "$body"; fi
    printf 'Upstream-Commit: %s\n' "$commit"
  } >"$message"

  name=$(git -C "$upstream" log -1 --format=%an "$commit")
  email=$(map_email "$(git -C "$upstream" log -1 --format=%ae "$commit")")
  date=$(git -C "$upstream" log -1 --format=%aI "$commit")
  GIT_AUTHOR_NAME="$name" GIT_AUTHOR_EMAIL="$email" GIT_AUTHOR_DATE="$date" \
    git commit -q -F "$message"
  rm -f "$message"
  mirrored=$((mirrored + 1))
  echo "Mirrored ${commit:0:12}: $subject"
done

# Release tags: observer-vX.Y.Z upstream becomes vX.Y.Z on the mirrored commit
# with exactly the same tree.
tagged=0
for upstream_tag in $(git -C "$upstream" tag --list 'observer-v*'); do
  tag=${upstream_tag#observer-}
  if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
    continue
  fi
  target=$(git -C "$upstream" rev-list -n 1 "$upstream_tag")
  if ! git -C "$upstream" merge-base --is-ancestor "$target" "$head"; then
    echo "Skipping $upstream_tag: not on upstream $branch." >&2
    continue
  fi
  want=$(git -C "$upstream" rev-parse "$target:$prefix")
  match=""
  for candidate in $(git log --format=%H -n 500); do
    if [ "$(git rev-parse "$candidate^{tree}")" = "$want" ]; then
      match=$candidate
      break
    fi
  done
  if [ -z "$match" ]; then
    echo "Skipping $upstream_tag: no mirrored commit has its exact tree." >&2
    continue
  fi
  git tag "$tag" "$match"
  tagged=$((tagged + 1))
  echo "Tagged $tag on ${match:0:12}"
done

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "mirrored=$mirrored"
    echo "tagged=$tagged"
  } >>"$GITHUB_OUTPUT"
fi
echo "Mirrored $mirrored commit(s), created $tagged tag(s)."
