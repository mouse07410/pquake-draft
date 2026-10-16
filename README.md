<!-- regenerate: off (set to off if you edit this file) -->

# PQuAKE - Post-Quantum Authenticated Key Exchange

This is the working area for the individual Internet-Draft, "PQuAKE - Post-Quantum Authenticated Key Exchange".

* [Editor's Copy](https://mouse07410.github.io/pquake-draft/#go.draft-uri-cfrg-pquake.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-uri-cfrg-pquake)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-uri-cfrg-pquake)
* [Compare Editor's Copy to Individual Draft](https://mouse07410.github.io/pquake-draft/#go.draft-uri-cfrg-pquake.diff)


## Contributing

See the
[guidelines for contributions](https://github.com/mouse07410/pquake-draft/blob/gh-pages/CONTRIBUTING.md).

Contributions can be made by creating pull requests.
The GitHub interface supports creating pull requests using the Edit (✏) button.


## Command Line Usage

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

The local Makefile adds three explicit steps around the external template:

| Command | Result |
| --- | --- |
| `make next` | Build numbered HTML/XML/TXT previews under `versioned/`; no tag or push. |
| `make release` | Rebuild and lint committed sources, then create an annotated local release tag. |
| `make publish` | Push only the latest annotated release tag at HEAD to `origin`. |

Commit all source changes before `make release`. It rejects staged,
unstaged, and untracked files, validates the outputs, and verifies that
HEAD and the source tree did not change during the build. A failed check
does not create a tag. Release and publish operations share a lock across
worktrees; if a process is forcibly killed, check that it has stopped
before removing the Git common directory's `pquake-release.lock` directory.

The preview revision is one greater than the latest local release tag;
repeated `make next` calls keep that number until another release is tagged.
For example, with `-01` tagged, the next preview and release are `-02`.
Existing output files do not advance the number. The historical local tag
`draft-uri-cfrg-pquake-00` identifies commit `f8f20c2`, whose archived
editor's copy matches the submitted `-00` text.

`make release` refreshes cached revision rules and runs `make next lint`
with source rebuilding enabled. It disables automatic template updates and
branch fetching during validation. It refuses to release HEAD again if
that commit already has the latest release tag, and refuses to advance
past the two-digit revision `99`. Fetch any missing release tags before
preparing a release so numbering reflects the repository's release history.

After reviewing the generated files, run `make publish`. It requires a clean
source tree and the latest annotated release tag at HEAD. It pushes one
explicit tag without force or automatic following of other tags; it does
not push `main`. Select another configured remote with
`make publish RELEASE_REMOTE=REMOTE_NAME`. The resulting GitHub Actions run
uploads the draft to Datatracker, which then requests author confirmation
by email. A successful Git push is not confirmation that Datatracker has
posted the revision. Dry-run modes such as `make -n release` and
`make -n publish` do not create tags or push.
Run `make publish` on its own, rather than mixing it with build goals. This
entry point bypasses the external template's older direct-upload alias and
does not load converters or invoke `make upload`.

After creating a release tag, `make next` previews the following revision.
To rebuild an existing release, request its explicit targets instead:

```sh
make versioned/draft-uri-cfrg-pquake-01.html \
     versioned/draft-uri-cfrg-pquake-01.xml \
     versioned/draft-uri-cfrg-pquake-01.txt
```

`make test-release` runs integration tests with disposable Git repositories
and stubbed converters, including failed validation, changed sources,
revision limits, dry runs, and publication to a local bare repository.
It does not submit a draft or contact a remote hosting service.

Release tags must be available in the checkout for revision numbering.
CI fetches full history and tags. Pushing a `draft-*` tag triggers the
Datatracker submission workflow; restoring a historical tag locally does
not submit the draft.

The Makefile sets `DEFAULT_BRANCH=main` so the Pages publishing target puts
the editor's copy at the site root, including
[the HTML draft](https://mouse07410.github.io/pquake-draft/draft-uri-cfrg-pquake.html).
Other branches are published in preview subdirectories. This build setting
is separate from the Pages source branch, `gh-pages`, which stores generated
output. Changes reach the public site after the `Update Editor's Copy`
workflow and the subsequent Pages deployment succeed.

Command line usage requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).

