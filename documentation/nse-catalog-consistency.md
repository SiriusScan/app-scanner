# NSE catalog consistency

The NSE catalog is shared by the scanner, the UI store router, and the REST
script API. Deploy all three changes together with the SDK atomic-store helper.
An old whole-manifest writer can still erase ownership and deletion markers.
No production migration or deployment is performed by these source changes.

## Ownership and deletion

- `nse:manifest.scripts` is the index. New repository entries carry
  `source: {"type":"repository","repository":"<configured name>"}`.
- New UI and REST entries carry `source: {"type":"custom"}`. Protocol is
  execution metadata, not an ownership marker. Existing unmarked entries are
  preserved without guessing whether a user or an old scanner created them.
- Scanner sync aggregates all configured repositories before publishing. Global
  canonical IDs must be unique and idempotent under canonicalization (for
  example, `foo.nse.nse` is rejected). Conflicting repositories or aliases fail safely
  rather than choosing an arbitrary winner. A script cannot silently change
  repository ownership.
- Only explicitly repository-owned index entries are pruned when a script or
  repository disappears. Content envelopes are retained because they may contain
  user edits. This is deliberate preservation, not an active index entry. An
  explicit future content-cleanup or legacy-ownership migration needs a separate
  policy; the sync does not infer one.
- Deleting a script removes its index entry and body in the same transaction and
  records `deletedScripts[canonicalID] = true`. Sync honors this marker even if the
  script still exists in a repository. Explicit create can clear the marker.
- Existing endpoint policies stay distinct: UI deletion can remove any catalog
  entry; REST deletion permits custom entries (including legacy protocol `custom`)
  and rejects explicitly repository-owned entries.
- Catalog deletion is not a new Nmap execution-deny policy. Repository files and
  Nmap's own installed/default scripts are not removed. Existing direct script
  selections and wildcard defaults remain unchanged.

## Atomicity and failure behavior

The optional SDK `store.AtomicValueUpdater` performs multi-key compare-and-swap.
Every write is guarded by its prior exact value or confirmed absence. Scanner
publication guards repository configuration, the current catalog, and every
relevant content slot. UI/REST mutations guard the catalog and target content
slots. Repository-list add/remove/initialization also use single-key CAS so
concurrent configuration changes cannot erase an unrelated repository. Existing
empty repository lists remain empty instead of resurrecting defaults. The UI's
generic setter rejects the reserved script, catalog, and repository-list keys.
A conflict causes a bounded reread/revalidation, never an unconditional retry.
Unsupported atomic stores fail rather than degrade to GET/SET.

Initial content and the catalog publish together. A concurrent custom creation,
edit, deletion, or repository removal cannot be overwritten by a stale sync.
Legacy content keys are migrated with their canonical target in the same CAS;
multiple existing aliases are rejected for explicit repair. Unknown catalog and
entry fields are retained. Malformed catalogs, ambiguous ownership, and store
read failures do not trigger replacement with defaults. A malformed individual
script body is reported, is not written to disk, and does not prevent valid
scripts from synchronizing.

Valkey operations are atomic; filesystem and Valkey are not one distributed
transaction. Local files are written with same-directory temporary files and
rename after a successful store publication. A filesystem failure is reported
and a later sync can retry. A content edit after publication may require a later
sync to appear in a local file. Symlink script paths and lexical traversal are
rejected. This is not protection against an actively hostile process swapping
filesystem components concurrently.

A timeout or transport error after a CAS may have an uncertain outcome. Callers
return that error instead of blindly retrying. Clustered Valkey requires all
transaction keys in one hash slot; current NSE key names target the existing
single-node deployment.

The old `UpdateValKeyManifest` helper is now an additive, atomic merge. It cannot
replace the catalog with an empty manifest. In particular, `cmd/nse-reset --force`
no longer clears custom entries or deletion markers through that helper and will
report an error. Use normal `Sync` for reconciliation; a destructive reset needs
an explicitly designed administrative operation.

## Verification and remaining release gates

Synthetic scanner fixtures cover custom/legacy preservation, multiple repos,
ownership pruning, duplicate IDs, invalid repositories/catalogs, legacy bodies,
concurrent create/edit/delete/configuration changes, cancellation, unsupported
stores, missing custom content, and symlink paths. REST uses fake stores; UI uses
mocked client tests. Actual UI Lua also passed on a fresh disposable Valkey 8
container: 50 forced create conflicts, 150 mutation cycles, and 1,670 atomic
read snapshots preserved the index/body/deletion invariants. SDK atomic Lua was
also tested on a fresh disposable Valkey 8 container, with race detection for
concurrent callers. No live application
store or scanner target is used by those focused tests.

The workspace uses local SDK replacement for API/scanner validation. Publish the
additive SDK and update consumer dependency pins before a release. Do not deploy
only the scanner while old UI/REST writers remain active. Preserve a backup and
review legacy unowned/orphan content before any separate migration or cleanup.

## Reproducible functional checks

From the sibling `Sirius/sirius-ui` checkout, run:

```sh
bash scripts/test-nse-valkey.sh
bash scripts/test-nse-workflow.sh
```

These runners require already installed UI/Go dependencies, Docker, and the
already available `valkey/valkey:8-alpine` image. They use `--pull=never`, fresh
loopback ports, explicit disposable-store markers, no persistence, and cleanup
traps. They do not run the application containers, connect to application stores,
clone repositories, or launch scanner targets. Go phases use the local SDK via a
temporary module file without changing dependency pins.

The full workflow executes actual scanner `Sync`, UI Lua mutations, Fiber REST
HTTP handlers, and UI content readers against the same disposable server. It
then repeats scanner sync and confirms the following:

- Uppercase `.NSE` identities remain distinct and deleted scripts stay deleted.
- Scripts from two repositories and user-created entries remain indexed.
- UI overrides and unknown metadata survive REST updates and scanner refreshes.
- Legacy raw keys migrate only with their bodies; independent paths are not IDs.
- Duplicate IDs reject before any catalog mutation.
- New REST omitted-tag records and old `tags:null` records are readable/editable.

Additional regressions were demonstrated failing before correction: REST null
arrays rejected by the UI, scanner-published IDs rejected by the UI, and repeated
SDK integration-test runs leaking fixed keys. Six actual-router repository-list
regressions also demonstrated lost updates and duplicate-creation races before
the configuration CAS fix. The shared SDK atomic test now uses unique keys, cleans them up, and passes 20 repeated race-enabled runs.

UI and Go canonicalization now share basename plus lowercase-only `.nse` suffix
removal, without whitespace trimming. IDs must match the shared allowed
character pattern and be stable under another canonicalization pass. This
prevents aliases such as `foo.nse.nse` from changing identity between writers.
