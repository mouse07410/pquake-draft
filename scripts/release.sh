#!/bin/sh
# Purpose: prepare a validated PQuAKE release or explicitly publish its tag.
# Source: original repository-specific orchestration of i-d-template targets.
# Version: 1, 2026-10-16. Responsible party: PQuAKE repository maintainers.
# Inputs: $1 is release or publish; $2 is the recursive make executable.
# Environment: RELEASE_REMOTE selects a configured remote (default origin).
# Returns: zero on success; nonzero on invalid input, build, Git, or push failure.
# Exceptions: none; shell/Git errors stop processing without creating a later tag.
# History: initial implementation, 2026-10-16.
# Examples: make next; make release; make publish RELEASE_REMOTE=origin.
# No submission occurs during release. Publishing a draft-* tag starts the
# repository's submission workflow, which still needs author email approval.
set -eu

# Validate invocation and repository location before touching release state.
if [ "$#" -ne 2 ]; then
    echo 'Usage: release.sh release|publish MAKE_EXECUTABLE' >&2
    exit 1
fi
case "$1" in release|publish) ;; *) echo 'Unknown release operation.' >&2; exit 1 ;; esac
make_program=$2
test -n "$make_program"

# Recursive recipes run even with -n/-t/-q. Honor short or long options before
# any mutation. Stop at variable assignments and disable globbing while reading
# MAKEFLAGS: user-supplied variable values must never expand to local filenames.
set -f
for option in ${MAKEFLAGS-}; do
    case "$option" in
        --|*=*) break ;;
        --just-print|--dry-run|--recon|--touch|--question)
            echo "Skipped $1 in make preview/query mode."; exit 0 ;;
        --*) ;;
        *[ntq]*) echo "Skipped $1 in make preview/query mode."; exit 0 ;;
    esac
done
repo_root=$(git rev-parse --show-toplevel)
if [ "$(pwd -P)" != "$(cd "$repo_root" && pwd -P)" ]; then
    echo 'Run this target from the repository root.' >&2
    exit 1
fi

# Serialize release/publish operations, including across linked worktrees.
lock_dir=$(git rev-parse --git-common-dir)/pquake-release.lock
if ! mkdir "$lock_dir" 2>/dev/null; then
    echo "Release lock unavailable: $lock_dir (check for another release process)." >&2
    exit 1
fi
trap 'rmdir "$lock_dir"' EXIT
trap 'exit 1' HUP INT TERM

# source_commit is the state variable pinning the commit to validate and tag.
# Reject staged, unstaged, and untracked changes before invoking any builders.
source_commit=$(git rev-parse HEAD)
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    echo 'Commit or stash all source changes before release or publish.' >&2
    exit 1
fi
draft=draft-uri-cfrg-pquake
# latest_tag is the state variable used to select the revision for this run.
tags=$(git tag --list "$draft-[0-9][0-9]" --sort=-refname)
latest_tag=$(printf '%s\n' "$tags" | sed -n '1p')

case "$1" in
release)
    # Calculate the same two-digit revision as the template, without wrapping.
    if [ -z "$latest_tag" ]; then
        revision=00
    else
        if [ "$(git rev-parse "$latest_tag^{commit}")" = "$source_commit" ]; then
            echo 'HEAD already has the latest release tag; no new release was created.' >&2
            exit 1
        fi
        previous=${latest_tag##*-}
        if [ "$previous" = 99 ]; then
            echo 'Revision 99 cannot be incremented within the two-digit naming scheme.' >&2
            exit 1
        fi
        revision=$(printf '%02d' "$((1$previous - 99))")
    fi
    release_tag=$draft-$revision

    # Refresh cached tag-derived rules, then rebuild every numbered format and
    # run lint. Disable template updates and branch fetching during validation.
    "$make_program" .targets.mk UPDATE_NEEDED=false BRANCH_FETCH=false
    "$make_program" -W "$draft.md" next lint UPDATE_NEEDED=false BRANCH_FETCH=false
    for extension in html xml txt; do
        artifact=versioned/$release_tag.$extension
        if [ ! -s "$artifact" ] || ! grep -Fq "$release_tag" "$artifact"; then
            echo "Missing, empty, or incorrectly numbered release output: $artifact" >&2
            exit 1
        fi
    done

    # A build must not change the commit or source tree that is being tagged.
    if [ "$(git rev-parse HEAD)" != "$source_commit" ] ||
       [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
        echo 'Source changed during validation; no release tag was created.' >&2
        exit 1
    fi
    git tag -a "$release_tag" "$source_commit" -m "Release $release_tag (build and lint validated)"
    echo "Created local tag $release_tag at $source_commit."

    # Prime the template's cached rules with the newly added tag. Older make
    # versions otherwise need a second invocation after a tag-list change.
    if ! "$make_program" .targets.mk UPDATE_NEEDED=false BRANCH_FETCH=false; then
        echo 'Tag created; cached target refresh failed. Rebuild .targets.mk before the next preview.' >&2
    fi
    echo 'Review versioned/ outputs; run make publish to submit this release.'
    ;;
publish)
    # Select only the latest local release, and require its exact source commit
    # to be checked out. Do not infer another revision with make next here.
    if [ -z "$latest_tag" ] ||
       [ "$(git cat-file -t "refs/tags/$latest_tag")" != tag ] ||
       [ "$(git rev-parse "$latest_tag^{commit}")" != "$source_commit" ]; then
        echo 'Publish requires the latest annotated release tag at HEAD.' >&2
        exit 1
    fi
    remote=${RELEASE_REMOTE:-origin}
    case "$remote" in
        -*|*[!a-zA-Z0-9._-]*) echo 'RELEASE_REMOTE must be a configured remote name.' >&2; exit 1 ;;
    esac
    git remote get-url "$remote" >/dev/null

    # Push one explicit tag, overriding push.followTags and refusing tag rewrites.
    # GitHub Actions performs the upload; authors then confirm its email request.
    git -c push.followTags=false push --no-follow-tags "$remote" \
        "refs/tags/$latest_tag:refs/tags/$latest_tag"
    echo "Published tag $latest_tag. Check the submission workflow and author confirmation email."
    ;;
esac
