# Hermes Vault

Hermes Vault is the secret-custody layer for the Hermes Fleet vNext architecture.
It owns secret bodies and their lifecycle. Fleet owns authorization and run
lifecycle. Hermes Agent owns local execution. Those responsibilities stay
separate on purpose.

## Phase 14 contract

Vault provides:

- encrypted-at-rest secret bodies;
- explicit ownership by Fleet principal identity;
- principal, project, network, and owner scopes;
- stable opaque references that contain no principal, scope, target, or body;
- immutable material versions and rotation;
- expiry and revocation at the secret/version/run-handle boundaries;
- temporary handles bound to an exact run and RunAuthority hash;
- env, file, and internal broker injection descriptors;
- value-free access auditing.

Vault does **not** grant Fleet authority, widen RunAuthority, expose a model tool
for reading secret bodies, or put secret bodies into persistent Agent Instance or
Run Capsule state.

## Storage model

The default store root is `~/.hermes-vault`, overridable with
`HERMES_VAULT_HOME`.

- directory mode: `0700` on POSIX;
- master AES-GCM key: `master.key`, mode `0600`;
- SQLite metadata/ciphertext database: `state.db`, mode `0600`;
- opaque references and temporary handles are persisted only as SHA-256
  fingerprints;
- access audit rows contain identities, scopes, versions, injection descriptors,
  outcomes, and fingerprints, never secret bodies.

Secret bodies are encrypted with AES-GCM and authenticated against immutable
item/version/scope/injection metadata.

## Opaque references and run handles

A durable reference looks like `hvr1_<random>`. The string is an opaque
capability selector, not an authority grant. Every use is still checked against
the current principal/run scope.

A temporary handle looks like `hvh1_<random>`. It is bound to:

- exact run ID;
- exact principal identity/generation/binding;
- exact RunAuthority hash;
- exact material version;
- exact injection kind and target;
- bounded expiry and use count.

Rotation creates a new immutable version. New handles bind to the newest
version. Existing handles remain pinned to the version they were minted for
until expiry/revocation, preserving exact-run semantics.

## Injection descriptors

Vault records where trusted runtime code may inject material:

- `env:NAME` for per-command environment injection;
- `file:name.ext` for an ephemeral runtime file;
- `broker:service.name` for trusted internal tool/provider code.

The descriptor is safe metadata. The body is returned only from the runtime
handle redemption API.

## CLI

The CLI never accepts a secret body as a command-line argument. `put` and
`rotate` read bytes from stdin so values do not appear in shell history or
process arguments.

```bash
hermes-vault init

printf '%s' "$VALUE" | hermes-vault put \
  --principal-id sha256:... \
  --binding-hash sha256:... \
  --target-scope principal:sha256:... \
  --inject env:PROVIDER_KEY
```

Management operations require the exact owning principal. Project/network scope
may authorize runtime use by another principal, but does not transfer ownership
or rotation/revocation authority.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest -q
ruff check .
ruff format --check .
```

Licensed under AGPL-3.0-only.
