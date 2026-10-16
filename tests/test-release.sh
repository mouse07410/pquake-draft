#!/bin/sh
# Purpose: integration-test the real local Makefile targets and release helper.
# Source: original PQuAKE release workflow regression tests.
# Version: 1, 2026-10-16. Responsible party: PQuAKE repository maintainers.
# Inputs: none; run from the repository root through make test-release.
# Returns: zero if every scenario passes, nonzero on unexpected behavior.
# Exceptions: none; failed shell assertions terminate the test run.
# History: initial implementation, 2026-10-16.
# Example: make test-release NO_RUBY=true NO_NODEJS=true.
# Builds are stubbed to test orchestration without installing tools or sending
# submissions. Publication uses a disposable local bare repository only.
set -eu
source_root=$(pwd -P)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/pquake-release-tests.XXXXXX")
trap 'result=$?; if [ "$result" -ne 0 ]; then cat "$test_root"/*.log; fi; rm -rf "$test_root"' EXIT
trap 'exit 1' HUP INT TERM
draft=draft-uri-cfrg-pquake

# Each scenario starts with a real clean Git history and an annotated -00 tag.
for scenario in release first-release dirty staged untracked build-failure lint-failure \
    source-change head-change missing-output exhausted malformed \
    publish publish-dirty publish-untagged publish-lightweight publish-conflict publish-mixed \
    bad-remote missing-remote bad-operation bad-args wrong-directory locked dry-release dry-publish touch-release; do
    fixture=$test_root/$scenario
    mkdir -p "$fixture/scripts" "$fixture/lib"
    cp "$source_root/Makefile" "$fixture/Makefile"
    cp "$source_root/scripts/release.sh" "$fixture/scripts/release.sh"
    cd "$fixture"
    git init -q
    git config user.name 'Release Test'
    git config user.email release-test@example.invalid
    git config commit.gpgsign false
    git config tag.gpgsign false
    git config core.hooksPath /dev/null
    printf 'versioned/\n.targets.mk\n.build-calls\n' >.gitignore
    printf 'Original draft\n' >"$draft.md"

    # The external template is replaced with minimal deterministic builders.
    # Environment switches exercise failed builds and concurrent source edits.
    cat >lib/main.mk <<'EOF'
drafts_next := draft-uri-cfrg-pquake-$(if $(BUILD_REVISION),$(BUILD_REVISION),01)
VERSIONED := versioned
.PHONY: next lint .targets.mk
.targets.mk:
	@git tag --list | sed 's/^/# /' >$@
next::
	@echo next >>.build-calls
	@test "$${FAIL_BUILD:-false}" != true
	@mkdir -p versioned
	@for ext in html xml txt; do \
	  echo '$(drafts_next)' >versioned/$(drafts_next).$$ext; \
	done
	@if [ "$${MISSING_OUTPUT:-false}" = true ]; then rm versioned/*.txt; fi
lint:
	@echo lint >>.build-calls
	@test "$${FAIL_LINT:-false}" != true
	@if [ "$${EDIT_SOURCE:-false}" = true ]; then echo changed >>draft-uri-cfrg-pquake.md; fi
	@if [ "$${MOVE_HEAD:-false}" = true ]; then git commit -q --allow-empty -m concurrent; fi
# Catch accidental inheritance of the template's direct-upload publish alias.
publish: upload
upload:
	@echo unintended-direct-upload >>.build-calls
	@false
EOF
    git add .
    git commit -qm original
    if [ "$scenario" != first-release ]; then git tag -a "$draft-00" -m original; fi
    printf 'Revised draft\n' >>"$draft.md"
    git add "$draft.md"
    git commit -qm revised

    # Prepare the negative inputs without accidentally invoking real tools.
    case "$scenario" in
        dirty) echo dirty >>"$draft.md" ;;
        staged) echo staged >>"$draft.md"; git add "$draft.md" ;;
        untracked) touch unexpected-source ;;
        exhausted) git tag -a "$draft-99" HEAD~1 -m exhausted ;;
        malformed) git tag "$draft-999" ;;
        publish|publish-dirty|publish-untagged|publish-lightweight|publish-conflict|publish-mixed|\
        bad-remote|missing-remote|dry-publish)
            if [ "$scenario" = publish-lightweight ]; then
                git tag "$draft-01"
            else
                git tag -a "$draft-01" -m prepared
            fi
            git init -q --bare "$test_root/$scenario-remote.git"
            git remote add origin "$test_root/$scenario-remote.git"
            git config push.followTags true
            ;;
    esac

    # Dispatch the real Makefile targets with only local fixture dependencies.
    target=release
    case "$scenario" in publish*|bad-remote|missing-remote|dry-publish) target=publish ;; esac
    case "$scenario" in
        publish-dirty) echo dirty >>"$draft.md" ;;
        publish-untagged) git commit -q --allow-empty -m later ;;
        locked) mkdir .git/pquake-release.lock ;;
        publish-conflict)
            git --git-dir="$test_root/$scenario-remote.git" fetch -q "$fixture" \
                "refs/tags/$draft-00:refs/tags/$draft-01"
            ;;
    esac
    export FAIL_BUILD=false FAIL_LINT=false EDIT_SOURCE=false MOVE_HEAD=false MISSING_OUTPUT=false
    export RELEASE_REMOTE=origin
    export BUILD_REVISION=01
    make_mode=
    case "$scenario" in
        first-release) BUILD_REVISION=00 ;;
        build-failure) FAIL_BUILD=true ;;
        lint-failure) FAIL_LINT=true ;;
        source-change) EDIT_SOURCE=true ;;
        head-change) MOVE_HEAD=true ;;
        missing-output) MISSING_OUTPUT=true ;;
        bad-remote) RELEASE_REMOTE=--all ;;
        missing-remote) RELEASE_REMOTE=missing ;;
        dry-release|dry-publish) make_mode=-n ;;
        touch-release) make_mode=-t ;;
    esac
    status=0
    # Avoid inheriting the parent's make variables, jobserver, or live CI settings.
    case "$scenario" in
      bad-operation) sh scripts/release.sh invalid make >"$test_root/$scenario.log" 2>&1 || status=$? ;;
      bad-args) sh scripts/release.sh release >"$test_root/$scenario.log" 2>&1 || status=$? ;;
      wrong-directory)
        (cd scripts && sh release.sh release make) >"$test_root/$scenario.log" 2>&1 || status=$? ;;
      publish-mixed)
        env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL -u GNUMAKEFLAGS \
            make next publish CI=true >"$test_root/$scenario.log" 2>&1 || status=$? ;;
      *) env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL -u GNUMAKEFLAGS \
            make $make_mode "$target" CI=true >"$test_root/$scenario.log" 2>&1 || status=$? ;;
    esac

    # Check both the intended result and absence of an unintended release tag.
    case "$scenario" in
        release|malformed)
            test "$status" -eq 0
            test "$(git cat-file -t "refs/tags/$draft-01")" = tag
            test "$(git rev-parse "$draft-01^{commit}")" = "$(git rev-parse HEAD)"
            test "$(cat .build-calls)" = "$(printf 'next\nlint')"
            grep -Fq "$draft-01" .targets.mk
            for ext in html xml txt; do test -s "versioned/$draft-01.$ext"; done
            # Releasing unchanged HEAD again must fail without consuming -02.
            if env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL -u GNUMAKEFLAGS \
                make release CI=true >>"$test_root/$scenario.log" 2>&1; then exit 1; fi
            ! git show-ref --verify --quiet "refs/tags/$draft-02"
            ;;
        publish)
            test "$status" -eq 0
            git --git-dir="$test_root/$scenario-remote.git" show-ref --verify --quiet "refs/tags/$draft-01"
            ! git --git-dir="$test_root/$scenario-remote.git" show-ref --verify --quiet "refs/tags/$draft-00"
            test ! -e .build-calls
            ;;
        first-release)
            test "$status" -eq 0
            test "$(git cat-file -t "refs/tags/$draft-00")" = tag
            ;;
        dry-release|touch-release|dry-publish)
            test "$status" -eq 0
            test ! -e .build-calls
            if [ "$scenario" = dry-publish ]; then
                test -z "$(git --git-dir="$test_root/$scenario-remote.git" tag --list)"
            else
                ! git show-ref --verify --quiet "refs/tags/$draft-01"
            fi
            ;;
        publish*|bad-remote|missing-remote)
            test "$status" -ne 0
            test ! -e .build-calls
            ;;
        *)
            test "$status" -ne 0
            ! git show-ref --verify --quiet "refs/tags/$draft-01"
            ;;
    esac
    echo "PASS: $scenario"
    cd "$source_root"
done
