# Publishing this initial handoff

The handoff includes a local Git repository and a Git bundle. **No public GitHub
repository was created and no commits were pushed from the authoring session.**
The connected GitHub tool exposed reads but no create/push operation, no alternate
write integration was available, and there was no authenticated `gh` CLI.

From the directory containing the downloaded bundle:

```sh
git clone jevproc-0.1.0rc1.bundle jevproc
cd jevproc
git remote remove origin
gh auth status
gh repo create alexykn/jevproc --public --source=. --remote=origin --push \
  --description "Read-only process triage with Jev; warnings-first, no Rich."
git push origin v0.1.0rc1
```

Authenticate with `gh auth login` first when needed. These commands assume
`alexykn/jevproc` does not already exist. Do not force-push over an existing project.
The source ZIP does not include Git history; use the bundle for the committed
initial implementation and local release-candidate tag.

GitHub documents the `--source`, `--public`, `--remote` and `--push` workflow at:
https://cli.github.com/manual/gh_repo_create

After publishing, inspect the CI run on both operating systems. CI does not require
TypeSafe credentials or a real process-risk judgment. Complete the deferred checks
in VALIDATION.md before treating this integration candidate as a validated
security tool. A Git tag is not a claim of empirical detection performance.

Publishing the source does not enable private security reports, publish to PyPI,
create a GitHub Release or attach binaries. Those remain separate owner actions.
