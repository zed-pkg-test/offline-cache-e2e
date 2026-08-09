# `zed-tool` frozen offline profile certification

Tracking: DEN-2923, DEN-1437, DEN-1482, DEN-1442

This repository independently certifies the staged product command from
`zed-pkg/zed-cli`:

```console
zed-tool --lock .zed/environment.lock.json --json verify --portable
zed-tool --lock .zed/environment.lock.json --json list --target <target>
zed-tool --lock .zed/environment.lock.json --json install \
  --target <target> --offline --home <zed-home>
```

The exact candidate commit is stored in `.zed-tool-candidate-ref`. Manual
workflow overrides must also be full 40-character commits. The workflow checks
out the exact shared `zed-interfaces` revision recorded by the candidate and
rejects disagreement between `Cargo.toml`, `Cargo.lock`, and the certification
pin.

## Black-box boundary

`scripts/zed_tool_offline_profile.py` imports no implementation module from
`zed-cli` or `zed-interfaces`. It constructs:

- one deterministic `tar.gz` containing a small platform-native command;
- one exact manager-neutral `EnvironmentLock` JSON document;
- one content-addressed local cache entry; and
- disposable project, Zed home, profile, and store roots.

It then drives only the compiled `zed-tool` executable. Ubuntu 24.04, macOS 15,
and Windows Server 2025 each certify:

- portable lock verification and exact-target listing;
- frozen installation from authenticated local cache bytes;
- execution of the installed command and alias;
- byte-stable `unchanged` replay;
- a second project reusing the same cache and content-addressed store;
- missing-cache, changed-hash, wrong-size, executable-collision, online-mode,
  plan-digest, and unsafe-target rejection before profile creation;
- a project-relative, secret-free `profile.json`; and
- immutable harness, product, and interface checkouts.

A malformed credentials file, fake Zed token, unreachable registry, and failing
HTTP/HTTPS/ALL proxy are present during the black-box run. Success therefore
cannot depend on credential parsing, registry discovery, or network fallback.
The harness executes the installed fixture command itself only after product
installation succeeds; `zed-tool` remains responsible solely for verification,
safe extraction, store publication, and profile activation.

## Product-quality gate

A separate Ubuntu job runs candidate formatting, the focused library and
compiled CLI tests, and strict Clippy against `zed-tool` and its integration
target. The external gate complements rather than replaces the candidate's own
permanent product workflow.

## Security and evidence

The workflow has `contents: read` only, uses full-SHA Action pins, disables
persisted checkout credentials, and owns all mutable state below runner-temporary
directories. It receives no GitHub PAT, Linear token, Cloudflare/R2 credential,
registry credential, signing material, or OIDC permission.

Successful platform jobs retain only `result.json` and the command transcript
for seven days. Failed jobs retain bounded logs and checkout status; they do not
upload cache archives, store contents, credentials files, or tool-profile
payloads.

The current slice does not certify downloads, version discovery, signatures,
multiple active versions, backend plugins, global PATH mutation, lazy shims,
update/prune, or `zed dev` activation. Those remain separate product and
certification slices.
