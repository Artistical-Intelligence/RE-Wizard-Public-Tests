# Public test companion instructions

This repository intentionally publishes a small, fixed selection of original
implementation code and original synthetic tests.

- Only files listed in `tools/check_public_tree.py` belong here.
- Never add games, compiler archives/binaries, vendor/reference code, real dumps,
  private manifests/source revisions, credentials, personal information or logs
  containing private source material.
- Keep the two implementation files byte-identical to the reviewed export.
  Review any changed source bytes before updating `export-manifest.json`.
- Use only synthetic fixtures and temporary generated outputs. Do not execute
  guest code or download a private repository.
- Keep CI on standard GitHub-hosted runners with read-only contents permission,
  no private tokens, no self-hosted runner and no uploaded artifacts.
- Test results describe the exported components and exact hashes, not a full
  private-project or runtime verification claim.
- Before publishing, verify the complete file inventory and run the boundary
  check and synthetic test suite. Public history is permanent disclosure.
- Keep private export approvals, revision mappings and checker reports elsewhere.
- Preserve existing files and unrelated work; do not expand the public boundary
  automatically. Commits must use a nonpersonal author/committer identity.
