# Release rules (Grabbit's, for FortiConnect)

- **One version for everything:** `package.json`, `engine/`, `ui/`, `desktop/` (all via `npm version <v>
  --no-git-tag-version` so the lock files follow) and `ENGINE_VERSION` in `engine/src/http/server.ts`.
- **The tag is `v<version>`** and must match `desktop/package.json`; the release workflow refuses anything else. Every
  release needs `docs/release-notes/v<version>.md` (the workflow uses it as the release body).
- **Release assets have no spaces in their names** (GitHub would rename them and break `latest*.yml`). The
  `artifactName` patterns in `desktop/electron-builder.yml` set this; keep them.
- **The auto-updater contract:** installed copies read `latest.yml` (Windows), `latest-mac.yml` and `latest-linux.yml`
  from the newest release of `amirerajabi/forti-connect` (`publish:` in `electron-builder.yml`). The release workflow checks
  that all three exist, name this version and point at uploaded files. Never remove those checks.
- **A version that shipped is never rebuilt under the same number.** Installed copies compare versions, not checksums.
  Fix forward with the next patch version.
- **The Windows installer ships OpenConnect:** the release workflow runs `scripts/fetch-openconnect.mjs`, which puts the
  OpenConnect project's own Windows build (pinned by SHA-256) into `desktop/core` (shipped as `resources/core`). To move
  to a newer OpenConnect, change its version and hash there and bump `HELPER_VERSION` so installed helpers take the new
  copy. macOS and Linux users install OpenConnect / strongSwan themselves. Locally `desktop/core` stays empty (git
  ignores it) unless you run the script.
- **Unsigned builds:** SmartScreen warns on Windows and macOS cannot auto-install (the updater only announces). The
  release notes say how to get past the warnings.
- **Publishing is public:** push, tag and release only when the user asked in this session. A release can be hidden with
  `gh release edit <tag> --draft=true`; ask before deleting a release or a tag.
