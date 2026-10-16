# Changes

## 2026-10-16

- Added `make release` to rebuild numbered preview files, run lint, and
  create an annotated local tag only after successful validation of a
  clean, unchanged source commit.
- Added `make publish` to push only the latest annotated release tag at
  HEAD, leaving Datatracker submission and email confirmation to the
  existing workflow. Dry runs do not tag or publish.
- Added release workflow integration tests using isolated local Git repos.
- Kept conversion rules in the external template and documented preview,
  release, publication, and rebuilding an already tagged revision.
