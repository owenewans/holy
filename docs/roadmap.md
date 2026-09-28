# Holy roadmap

## Current state

- [x] Boot the x86_64 live ISO, prepare a blank GPT guest disk in holyinstall,
  install the target root, then boot the installed disk through BIOS and UEFI
  under QEMU/TCG. The installed guest checks dinit, holypkg, package repair
  and local password login; a wrong password is rejected. A separate i686
  BIOS install-to-disk gate is recorded below.
- [x] Install a static OpenDoas package in the same artifact-approved
  holyinstall set transaction as the base system. BIOS and UEFI boots authenticate the
  local account and then run the scoped BusyBox UID command through doas;
  the PTY probe supplies its password and checks UID 0. The fixture uses a
  local shadow account and does not cover PAM/NSS or an account menu.


## Package manager

- [x] Add a direct `holypkg run SOURCE:PACKAGE -- COMMAND` launcher for an
  installed executable, with source-slot selection, manifest verification,
  argv/exit preservation, and manifest-derived private-bin PATH priority.
  The fixture installs a static executable in a disposable root. An explicit
  `--view PUBLIC=PRIVATE` bind mounts a package-owned private file or directory
  over an existing public path of the same type in a private user/mount namespace, then
  enters the target root. The fixture checks absolute helper lookup, argv,
  exit status and host path isolation. Automatic private conflict placement,
  missing public mountpoints and privileged fallback remain open.
- [x] Publish a native index generation with an optional Ed25519 signature
  before switching `current`; verify the exact index bytes and package
  artifacts against a supplied public key. Signed HTTPS mirrors check the
  signature before package downloads. Freeze source keys outside the source
  ID, enforce them during sync and bound catalog reads, and carry them through
  holygetiso's effective config. Wrong keys and changed signatures fail local
  fixtures. The signed HTTPS fixture still needs a network-enabled run.

- [x] Bind explicit non-native architecture placement decisions to individual
  selected artifact hashes, the plan and the recovery journal. Preserve host and
  target in installed state and check output, retain decisions for reused
  providers, and reject inheritance by new update artifacts. Cached replacements
  now accept a fresh artifact-scoped decision, including simultaneous setuid
  approval; recovery checks both journal decisions. Automatic runtime capability
  detection remains open.

- [x] Install direct hardlinks after their regular payload, validate inode groups,
  restore missing anchors from surviving members, and recover interrupted link
  creation/removal. Scan ELF facts at every hardlink path and retain hardlinked
  manual names in documentation bundles. Native pack and manifest generation
  detect shared inodes, select deterministic anchors and preserve direct links,
  including forward archive references. External aliases stay outside packages.

- [x] Update cached hardlink groups with shared staging inodes, preserve retained
  anchors, and support content/mode changes, membership changes, anchor moves and
  splits/merges. Retain group staging links through database publication and
  validate topology during recovery and cleanup. Reject undeclared inode sharing
  within installed manifests.

- [x] Resolve pacman package version constraints before passing exact candidate
  identities to libsolv. Preserve the comparator family, apply arch/libc scopes,
  reject cross-family constraint satisfaction, and validate updates against
  installed consumer constraints. Run 92 upstream comparison cases and solver /
  transaction fixtures. The separate Debian comparator covers epoch, tilde and
  revision. An explicit Holy native comparator covers numeric versions and
  prereleases; remaining foreign comparators remain open.

- [x] Resolve declared package aliases using their own versions and artifact ABI
  scopes. Preserve claims and their hash in holy-instance-4, discover installed
  aliases, and reject updates dropping required capabilities. Read legacy state
  through verified cached artifacts when alias metadata is needed. Build
  claims still need dependency resolution support.
- [x] Resolve unversioned literal file requirements from verified nondirectory
  payload paths, including links. Preserve the chosen owner in installed graphs;
  reject removal that breaks a consumer. Declared file claims alone do not
  satisfy a requirement. Versioned file requirements and cross-source lookup
  remain open.
- [x] Resolve unversioned bare command requirements from executable payloads
  in standard bin directories, including links to an executable in the same
  artifact. Reject claim-only and nonexecutable candidates; retain command
  edges through installation and removal checks. Custom PATH, shell builtins,
  versioned command requirements and private launcher mappings remain open.

- [x] Build gzip, LZ4, Zstandard, XZ and bzip2 codecs into the static musl client.
  Verify foreign import and native install/check/remove in a chroot without
  dynamic libc or external decoders; reject truncated compressed inputs.

- [x] Import local pacman binary archives through libarchive into verified native
  outputs, preserve original artifacts and metadata, classify/split known ELF ABIs,
  and bind outputs with a conversion receipt. Fixtures cover an actual gzip
  PKGINFO, links, malformed archives, inactive hooks and data installation.
  Repository sync, publisher verification, config files, recipe import and full
  foreign relation/hook/transform installation remain open.

- [x] Import local Debian .deb binary archives into native outputs with original
  ar bytes, control fields and scripts retained. Check ar order, 2.x version
  headers, optional post-data members, codec suffixes, payload paths,
  architecture claims and install/check/remove for a data package.
  Resolve Depends entries including OR alternatives and exact/unversioned
  Provides claims with Debian version ordering within the deb family.
  Automatic cross-source discovery probes each branch of a missing OR group;
  the solver checks branch versions after staging candidates.
  Pre-Depends and other unsupported relationships stay foreign requirements; conffiles require
  a decision. Verify listed `control/md5sums` files against the payload before
  conversion; the original MD5 list is not source authentication. A pinned
  local or HTTPS APT Packages index with an explicit pin now supports name search, exact package metadata,
  HTTPS fetch with artifact hash/size checks, and optional .deb import. A
  Release.gpg path now verifies a user-selected OpenPGP keyring, suite,
  Valid-Until when present, and signed index hash/size; catalogs keep evidence
  for rechecking. Registered APT sources now pin an OpenPGP keyring hash;
  sync-source and source-aware query/fetch check the source-id, URL and key.
  sync-source binds its catalog under the target database; source queries find
  that binding by suite, component and index architecture. Explicit
  --inrelease verifies clearsigned metadata through gpgv and rechecks it on
  query/fetch. Optional --files fetches a signed Contents index and supports
  exact path lookup, including source-bound catalogs. Coverage is marked
  partial; an absent match stays unknown. It remains a hint until
  the selected payload confirms the file. apt fetch --import --require-file
  checks the Contents hint and the converted .holy payload before recording
  a file provider in its fetch receipt. An inverted index, automatic candidate
  fetch, solver integration and full hook integration remain open.

- [x] Import local Slackware .txz/.tgz/.tbz/.tlz packages into native outputs.
  Preserve original bytes, filename identity/build tag, install/ metadata and
  review-required doinst.sh. Classify mixed x86/x86_64 ELF payloads, reject
  unsafe archive paths and unknown architecture, and install/check/remove a
  converted data package. Offline fixtures cover codecs and links; manual
  imports of Slackware 15.0 aaa_base and which archives passed. Repository
  discovery, publisher signatures and dependency metadata beyond the archive
  remain open.

- [x] Import local APK v2 binary packages with bounded gzip member parsing.
  Preserve control files and unverified signatures, check .PKGINFO datahash
  against the compressed data member, split observed ELF ABIs and keep
  simple package/SONAME/command dependencies as exact requirements and
  unsupported expressions as attributed foreign requirements.
  Offline fixtures cover two/three members, script review, data install,
  truncated/extra streams and unsafe paths. Manual imports of Alpine v3.22
  alpine-baselayout-data 3.7.0-r0 and scdoc 1.11.3-r0 passed. Supported APK v2
  version constraints use a family-specific comparator, checked against 841
  pairs from apk-tools 2.14.12; unrecognized forms remain foreign requirements.
  A rootless APKINDEX.tar.gz parser now retains the original signed or unsigned
  index, publishes a hash-bound local catalog and answers search/info without
  installation. An Alpine v3.22 main/x86_64 index with 5647 packages passed
  manual import and lookup. `apk fetch` now retrieves a selected package over
  HTTPS, checks index size and Q1 control checksum, .PKGINFO identity and
  datahash, and retains the original with a selection receipt. Local HTTPS
  fixtures and Alpine scdoc 1.11.3-r0 passed. Registered `type apk` sources now
  select a named repository for HTTPS index sync. A reviewed digest or explicit
  acceptance pins the index; fetch can recheck the active source-id and URL.
  Alpine v3.22 main/x86_64 with 5647 entries and scdoc fetch passed the
  registered-source path. Sync now binds the catalog to the source/repo in the
  target database; search, info and fetch can find it by source/repo. The
  binding detects catalog tampering and survives relocation of a target root.
  APKINDEX RSA signatures now verify against the registered public-key
  fingerprint. A `trust require` Alpine v3.22 main index with 5647 packages
  passed using the key extracted from `alpine-keys` 2.5-r0. That extraction
  tests signature mechanics; it does not establish the key's out-of-band
  authenticity. Keyed fetch now verifies the APK package signature over the
  compressed control member and records its result separately from the index.
  A signed Alpine scdoc 1.11.3-r0 fetch passed; local HTTPS fixtures reject
  missing keys, wrong keys and altered package signatures. Local APK import
  accepts an explicit RSA public key, verifies the package signature, and
  records algorithm and key fingerprint in each output origin. `apk fetch
  --import` now converts the verified download into `.holy`, rechecks the
  package hash and signature, and records the selected index hash and URL in
  output origin. Optional exact SONAME and file requirements check converted
  payload claims before the fetch receipt becomes complete. The signed HTTPS fixture
  installs, checks and removes an associated output in a disposable root.
  Feeding foreign candidates into the general resolver and full relation
  semantics remain open.

- [x] Parse `holy.conf` syntax and reject malformed includes and records.
- [x] Plan and atomically apply a source identity registry under the database
  writer lock. Preserve IDs across alias changes and retain inactive origin
  history; reject stale, wrong-root and history-dropping plans. Apply consumes
  the reviewed plan without rereading user includes. Automatic trust enforcement
  remains open.
- [x] Bind explicitly associated local artifacts to active registered source IDs
  in set plans and installed state. Retain the alias at installation, preserve
  origin through source deactivation and provider reuse, and validate associations
  during interrupted-set recovery. Signature evidence, automatic retrieval-origin
  binding and automatic update selection remain open.
- [x] Verify local LZ4-frame `.holy` archives, file manifests, hashes and basic ELF facts.
- [x] Read dynamic symbols, binding/visibility and per-symbol GNU versions through
  libelf, including ELF32/ELF64 without section headers when the hash tables give
  a symbol count. Preserve weak imports and compatibility/default versions.
  Symbol lookup order and dependency-provider validation remain open.
- [x] Classify static ET_EXEC without dynamic linkage as nolibc; reject
  unclassified ELF in native package scan rather than trusting a libc label.
- [x] Pack a prepared regular-file/dir/symlink/hardlink tree into a verified native `.holy`;
  reject unlisted inputs and unsupported file types before publication.
- [x] Generate a prepared DATA tree's regular-file/dir/symlink/hardlink HOLY/files manifest
  with numeric ownership and SHA-256; reject unsupported objects.
- [x] Stage verified objects in a target-root cache; preview collisions.
- [x] Fetch a pinned native `.holy` over HTTPS with certificate checks and a
  local CA fixture; reject credential-bearing redirect targets before making
  redirected requests. Signed generation discovery remains open.
- [x] Build and seal a local repository catalog; search and fetch its verified objects.
- [x] Resolve a restricted local/catalog graph with libsolv; reject unsupported semantics.
- [x] Validate every artifact in a proposed complete set, including consumers
  outside the selected update's dependency graph. Preserve disconnected packages
  and cycles, reject missing requirements and keep ambiguous provider edges
  decision-required. Update planning must still supply the proposed installed
  set and bind it to database generation, source and ownership decisions.
- [x] Add observed ELF interpreter, SONAME and strong symbol edges to that graph;
  reject candidate class/ABI/version/symbol mismatches and expose stable IDs for
  root provider choices. Unresolved launch scopes report unknown. Literal absolute
  provider paths now support dynamic set transactions; complete loader contexts remain open.
- [x] Export canonical selected artifact/edge records from the resolver; bind the
  supported install subset to its graph in the plan hash and installed state.
  Graph integrity checks preserve legacy state compatibility.
- [x] Journal installation, check and removal of `linux/nolibc` data and native static ELF
  artifacts into existing or explicitly declared safe directories. Recovery covers empty aborted installs,
  completed installs and interrupted removals under documented conditions.
- [x] Install relative symlinks with recorded targets and ownership; check, remove
  and recover them without following the links. Absolute links
  remain outside the transaction subset.
- [x] Query exact installed data-file ownership; report duplicate regular-file
  claims as conflicts while permitting shared directory entries.
- [x] Check one or all installed data manifests against the target root without
  downloads or repair; report each changed artifact in the all-packages pass.
  Emit machine-readable pass/fail summaries and per-path findings for this restricted check.
- [x] Check direct executable shebang interpreters for local `.holy` payloads
  inside the target root. Report unresolved `env`, malformed shebangs and
  interpreter chains as unknown; nested runtime dependencies remain open.
- [x] Reject existing directory mode/owner drift before data-only install;
  report installed directory drift in check without removing shared directories.
- [x] Compare installed slots by source-id, name, os, arch and libc. Permit distinct
  slots with compatible ownership and reject a second active version of one slot.
  Same-name glibc/musl executables run in the dual-libc chroot fixture. Multiple
  installed instances of the same artifact remain open.
- [x] Expose installed-slot check, manifest files and confirmed removal by
  SOURCE:PACKAGE. Resolve the recorded source ID through renamed or inactive
  aliases, require arch/libc selection for ambiguous slots, and keep files
  available when the live payload drifts. Source-instance fixtures cover the
  CLI and removal journal path.
- [x] Install a resolved cached static/data set with one writer lock, plan hash
  and generation change; persist reasons/edges, reject referenced-provider removal,
  and recover completed sets or resume untouched remaining packages after failure.
  The bootstrap image installs its base through this set engine.
- [x] Expose local .holy installation as holypkg add with explicit candidate
  archives, a displayed set plan, terminal approval or scoped --yes, and
  decision-required behavior without a terminal. Explicit root-artifact
  association resolves an active source alias to its immutable ID. Exact-hash
  CLI decisions permit non-native architecture placement and setuid payloads;
  the engine retains both in its plan and journal. Remote source lookup and
  hooks remain outside this local entry point.
- [x] Install glibc/musl dynamic sets with explicit interpreter and DT_NEEDED
  payload paths; execute real fixtures in a disposable x86_64 root. Report broken
  selected provider files through installed check. Ordinary SONAME search and
  automatic path conversion still require implementation.
- [x] Plan and journal missing-only repair from the verified artifact cache.
  Preserve changed/partial files, reject stale plans and resume recorded repair
  after injected write failure. Resolve installed `SOURCE:PACKAGE` for plan and
  apply; expose exact path ownership through `owner`. General reinstall and
  config merge remain open.
- [x] List native cache objects and require an explicit `cache clean SHA256 --yes`
  before deleting an unreferenced object. Hold database/cache locks, protect
  installed instances and hashes retained in transaction records, and reject
  incomplete transactions. `--accept-unavailable` permits reviewed removal of
  a referenced object, records its unavailable hash, and later staging clears
  the marker. Listing reports unavailable objects. Recovery of arbitrary
  external rollback references remains open.
- [x] Discover installed providers through package names and literal ELF paths;
  scan cached archives of the resulting candidate closure. Reuse intact version-2/3
  instances without changing their state, reason, graph or payload. Bind reused
  state into plans and validate it during interrupted-set recovery. Named loader
  search, automatic preference ranking and cache-independent discovery remain open.
- [x] Report orphan dependency instances by traversing saved edges from explicit
  roots. Ignore stale edges belonging to removed consumers; detect unreachable
  cycles and preserve shared providers. The read-only command works without cache
  artifacts and refuses incomplete, missing-provider or unknown-graph snapshots.
- [x] Show one shortest installed dependency path from an explicit root with
  `why SOURCE:PACKAGE`. Report an unreachable dependency as orphan and reject
  incomplete or malformed graphs. The source-instance and orphan fixtures
  cover graph traversal after package removal.
- [ ] Complete source-aware installed slots and version families; extend transactions to
  replacements, complete dynamic-library contexts and grouped removal. The
  explicit --accept-broken removal path now retains consumers and reports their
  broken edges; durable completed-transaction decisions remain unfinished.
- [ ] Install executable and shared-library payloads with ABI-aware linking,
  private providers, interpreter handling and explicit conflict decisions.
- [x] Install, run, check and remove a native static syscall-only ELF fixture;
  foreign-architecture approval remains open.
- [x] Resolve exact unversioned HOLY/deps SONAME records from scanned ET_DYN
  payloads, reject a forged typed claim, save the selected provider in the
  installed graph and prevent its removal. A selected foreign dependency now
  returns decision-required; an unused candidate can carry one without
  blocking a separate operation. A later set can find and reuse the installed
  SONAME provider from its cached archive, and a mismatched arch scope cannot
  reuse it. An unrelated ABI package needs no cache object for this lookup.
  A later set also discovers installed providers for ELF DT_NEEDED SONAME edges.
  Indexed installed SONAME lookup remains open.
- [x] Install a bare DT_NEEDED SONAME when the consumer has an ordered list of
  absolute or $ORIGIN-relative RUNPATH/RPATH directories and the chosen provider owns the
  first existing DIRECTORY/SONAME with matching ABI and required symbol versions.
  A provider-owned symlink chain to a versioned library is accepted. Cached
  replacements revalidate every selected SONAME edge. Installed check reads
  verified target-root ELF files and reports provider, alias or earlier-path
  shadowing drift. Other loader tokens and default search, cross-package aliases and
  plugins remain open.
- [x] Resolve direct absolute shebangs in native package sets against exact
  executable ELF paths. Save the selected provider edge, reject unresolved
  env/malformed scripts, block removal of a needed interpreter, and report
  installed interpreter drift. Resolve relative symlink chains in the supplied
  candidate set and protect each selected alias provider. Discover installed
  alias owners for a later script installation using root-confined lookup,
  including chains split between installed and new packages.
- [ ] Handle hooks, service consent, modified configs, overrides, rollback and
  recovery of each interrupted mutation phase.
- [x] Prepare regular-file and relative-symlink replacements beside their target,
  verify bytes and metadata before publication, and retry individual add/replace/
  remove transitions after interruption. Reject drift and preserve complete old
  or new files across injected rename failure and process termination. These
  primitives now support the journaled cached-update command below.
- [x] Compare verified old/new archive manifests into a canonical file plan with
  stable change IDs and both artifact hashes. Check the entire payload delta
  without writing files, accepting exact before/after states during recovery.
  Preserve unsupported entries in the record and reject their application.
  The cached update preview binds source, graph and ownership checks;
  directory creation is implemented below; directory metadata replacement remains open.
- [x] Preview one cached slot replacement with `db plan-update`. Bind the
  generation, root/database identities, every installed state, source registry,
  file delta and proposed complete dependency graph. Reject changed payloads,
  conflicting owners, disabled origins and unavailable old archives. Preserve
  source identity across alias changes. The single-slot catalog path below
  fetches candidates; new dependency selection and grouped replacements remain open.
- [x] Apply the reviewed cached replacement with one writer lock and generation
  change. Stage changed payload, journal individual transitions, publish the next
  installed database and retain the old records. Rewrite consumer edges while
  preserving reasons/source identity. Recover interrupted publication after
  injected SIGKILL and ENOSPC; preserve partial staging for explicit inspection.
  Test file addition/removal, regular/symlink transitions and a compatible ELF
  provider update. Hooks, config merging and general rollback remain open.
- [x] Prepare one source-aware slot update from a bound native catalog. Select
  the highest newer pacman/deb version or require an exact choice when version
  ordering is unknown, save the catalog digest and complete update plan, then
  apply only after whole-file hash approval and source/DB revalidation. A fixture
  covers upgrade, explicit downgrade and stale/tampered plans. Apply now checks
  the selected digest against the pinned index and installed slot before changing
  rootfs; a forged but internally consistent plan for an unlisted cached artifact
  fails. Grouped updates and trial execution remain open.
- [x] Apply a single-slot `up SOURCE:PACKAGE` in one invocation through the
  same hashed plan and checked apply path. Print the full plan, require a
  terminal decision or scoped --yes, and retain it for noninteractive review.
  The direct path tests both approval and decision-required behavior; updating
  all installed slots together remains open.
- [x] Read the pinned catalog index for an installed source slot and stage only
  matching name/os/arch/libc versions during update preparation. Verify those
  archives against the index before planning; keep the full catalog validation
  path for explicit source binding. Exact search, info and fetch now also verify
  only matching archives against the pinned index. A corrupt unrelated archive
  no longer blocks these operations. Older native indexes still require a full
  candidate scan during add.
- [x] Select the add candidate pool from v5/v6 native indexes by walking declared
  package/file/command/SONAME requirements and scanned interpreter, DT_NEEDED,
  shebang and symlink paths. Verify and stage only reachable archives; a corrupt
  unrelated object no longer blocks add, while a corrupt selected provider does.
  An in-memory inverted map resolves exact requirement names to indexed
  candidates without rereading every archive or rescanning every index entry.
  The pinned index and selected hashes remain bound to the reviewed plan.
  Cross-source discovery, indexed symbol versions and runtime dlopen probes
  remain open.
- [x] Require a fresh artifact-hash approval when a cached replacement contains
  a setuid executable. The plan, journal, installed state and recovery retain
  the decision; a previous package's approval is not inherited. Fixtures
  cover refusal, mode 4755 publication, injected ENOSPC recovery and removal
  of setuid on the next replacement. Privileged hardlinks remain unsupported.
- [x] Create missing manifest directories before payload installation, update or
  repair. Validate every absent parent, preserve existing modes/owners and publish
  prepared directories without replacement. Handle arbitrary archive entry order;
  recover exact staged/published directories in interrupted sets and updates.
  Reject symlinked parents, changed metadata and partially initialized staging.
  Retain directories and untracked contents on removal. Full directory metadata
  changes, privileged ownership and general single-install resume remain open.
- [ ] Implement native HTTPS/Git source synchronization, signed generations and
  cache retention with provenance.
- [x] Sync a registered holy-git source at an explicit full commit and native
  index digest. Verify all referenced artifacts and an optional registered
  Ed25519 signature, bind the sealed clone to its source-id, and reject a
  changed commit on later queries. A local Git fixture covers signed and unsigned
  sync, search, fetch, wrong pins and changed checkout metadata. Remote Git transport and
  multi-source resolution still need integration testing.
- [x] Accept a pinned holy-git commit in holygetiso source sections. Preserve
  the commit in the effective config and build record, pass it to source sync,
  and verify an imported clone before source binding. A local signed Git
  fixture covers image source staging and config validation.
- [x] Mirror an explicitly pinned HTTPS native catalog into a new sealed local
  snapshot through the common transport. Verify all artifact hashes, identity,
  payload and claims before publishing current; retain unsigned URL/digest
  provenance. Fixture TLS covers search/solve/fetch, escaped filenames, empty,
  duplicate/truncated indexes, false claims, bad hashes, missing URLs and limits.
  Signed generations use a separate Ed25519 sidecar; the signed HTTPS fixture
  still needs a network-enabled run.
- [x] Resolve an active registered holy-http alias to its immutable source-id
  and HTTPS URL, then mirror a pinned index into a new local catalog. An
  unsigned remote current pointer can propose a digest; a separate exact-hash
  confirmation rereads it before mirroring. Store source-id and selection in
  mirror-origin before sealing. Local TLS fixtures cover alias changes,
  unrelated backends, wrong digest, missing CA, changed/malformed pointers and
  credential-bearing redirects. Multi-source
  dependency resolution remain open.
- [x] Fetch one SOURCE:PACKAGE from an explicit sealed synced mirror without
  installing it. Check active source ID and URL against mirror provenance,
  verify the pinned index and selected archives, reject ambiguous names, and support extraction
  into a new directory.
- [x] Install SOURCE:PACKAGE from an explicit sealed holy-http mirror. Stage
  candidate artifacts, resolve dependencies in one set, bind newly selected
  packages to the registered source-id, and bind index digest to the reviewed
  plan and recovery journal. Reject changed catalogs before apply. A faulted
  generation update recovers from the version-5 journal without network access.
  Explicit `--candidate SOURCE:PACKAGE` combines bound catalogs in one reviewed
  set. `--candidate-provider SOURCE:KIND:NAME` stages exact indexed package,
  file, command or SONAME providers and their local closure. Both recheck each
  source before apply and preserve selected source IDs. The add loop now queries
  exact missing package, file, command and SONAME edges across active bound native
  catalogs before staging artifacts. It stages a unique matching source and its
  local closure. Multiple sources or unavailable coverage require a named alias
  in the terminal; noninteractive calls return decision-required. An explicit
  `--candidate-provider` selects the source. A three-source fixture checks both
  the noninteractive decision and terminal selection, then verifies installed files.
  `--answers FILE` now selects a source by consumer hash and requirement-id for
  noninteractive add; duplicate and stale answers fail before rootfs changes.
  It probes installed providers first, including inactive origins. Source preference
  ranking, complete coverage diagnostics and plugin discovery remain open. A
  three-catalog ELF fixture verifies SONAME discovery after installed libc and
  interpreter paths, selected source identity, and installed check. The source
  probe rejects a same-SONAME candidate without the consumer's version-attributed
  imported symbol.
- [x] Query an active holy-http source through an explicit synced mirror with
  `search QUERY --source ALIAS` and `info ALIAS:PACKAGE`. Verify source identity,
  pinned index and matching artifacts before returning exact names; report missing and
  ambiguous info queries without mutating the target. Native repositories also
  index verified nondirectory payload paths and support exact `search --file`
  with complete/unavailable coverage. File queries verify indexed candidates
  without reopening unrelated archives. Explicit `--fuzzy` returns ranked,
  capped hints for package names and file basenames, without treating them as
  exact providers. Search without --source visits active aliases in stable
  order, labels each result with its source ID and reports unavailable
  catalogs as incomplete coverage. Multi-source resolver integration remains
  open.
- [x] Add complete HOLY/deps records to native index generation 4. Verify the
  records against each selected archive, and expose `repo requirements` for
  a digest-pinned metadata query without opening the payload. The solver still
  scans archives for ELF-derived requirements; indexed candidate closure remains
  open.
- [x] Add scanned DT_SONAME facts to index generation 5. Exact provider lookup
  uses actual ET_DYN payload facts, then verifies selected archives; a forged
  HOLY/provides SONAME claim cannot become a candidate. Generation 6 adds
  per-library defined version names and checks strong ELF version needs before
  staging SONAME candidates. A targeted payload scan now rejects a matching
  SONAME/version candidate missing a strong imported symbol before staging.
  Cross-source offers apply the same consumer ELF probe. Generation 7 indexes
  exported dynamic symbols by library path, version and ELF attributes.
  Provider search rejects missing exports without opening candidate archives;
  selected artifacts are checked against the index and then by the resolver.
  Large-catalog index scaling remains open.
- [x] Bind a verified synced mirror and index digest to a registered source-id
  under the target database lock. Resolve add, fetch, search and info without
  repeating --catalog; reject corrupt bindings and changed mirrors. Keep the
  binding across alias renames. Sync without --output now publishes a verified
  generation in the target cache and binds it for source queries. A registered
  Ed25519 key now rejects unsigned or changed bound catalogs. A rootless
  system-cache workflow remains open.
- [ ] Implement remaining foreign binary adapters and file indexes with real
  fixtures: RPM, eopkg, homebrew and guix. APT has a pinned local index
  and HTTPS fetch/import path; APK has a separate index/fetch path.
  XBPS local binary import parses plist metadata, checks payload hashes and
  resolves simple versioned dependencies with a bounded Dewey comparator.
  It resolves relative archive symlink targets against absolute files.plist
  targets before comparing them, while retaining both original records.
  A pinned repodata catalog supports HTTPS sync, search, info and archive fetch.
  An explicit RSA public key can match index metadata and verify package .sig2.
  A registered XBPS source can now pin the RSA key, URL and source-id during
  sync-source, then bind the catalog conversion digest in the target database.
  Source-aware search/info/fetch resolve that binding by index architecture and
  reject changed catalog data or source definitions. Root-relative bindings
  survive moving a target root with its cache. A separate digest-checked
  shlib-provides index now gives exact SONAME candidate hints from Void metadata,
  including source-bound queries. Foreign binary import now derives SONAME
  provides from classified ELF payloads, so a selected archive can supply
  separate file-level evidence. Complex patterns remain review-required. Key enrollment,
  automatic provider selection and a file index remain open.
- [ ] Implement AUR, Aports, xbps-src, SlackBuilds, RPM spec, Debian source,
  Gentoo and Pacstall recipe conversion with helper environments and split outputs.
- [ ] Implement Nix closure, Flatpak, Snap, AppImage, Scoop and WinGet imports
  without silently discarding runtime requirements.
  AppImage type 2 inspect/extract now snapshots the original, checks ELF and
  SquashFS structure, extracts with unsquashfs without running the image, and
  records an unclassified AppDir plus per-file ELF, loader, script and link facts.
  `import --format appimage` preserves a source-attributed review bundle and
  returns decision-required without claiming a native package.
  Dependency closure, a launcher and .holy emission remain open.
- [ ] Implement `holypkg run`, context-specific provider paths, grouped `up --prepare`,
  isolated root/VM trials and full `check` reports.
  The existing run launcher now derives private PATH directories from the
  selected installed manifest, so a public executable can invoke its own
  private helper by name. Explicit directory views bind package-owned private
  trees over existing /usr/lib or /app mountpoints in the child namespace.
  Automatic conflict mappings remain open.

## Base system and images

- [x] Build musl-static dependencies, holypkg and holy-init for i686 and x86_64
  with explicit compiler and linker targets. Check ELF class/machine and pointer
  width, and run a static C package through pack/install/check/execute/remove
  under QEMU user mode (pentium2 or qemu64). The i686 client also passes codec
  import and DNS/HTTPS fixtures without dynamic libc on a compatible x86_64
  kernel. i686 BIOS boot and dinit's static C++ runtime are covered by separate
  gates below; compiler SDK packaging remains unfinished.

- [x] Generate an attributed installed-man source bundle with `holypkg docs`:
  verify source hashes, decode supported compressed pages, preserve aliases
  and same-name providers, report missing/omitted pages, and refuse changed
  inputs or pending transactions. Static gzip decoding passes a libc-free
  chroot fixture. The image builder generates its own bundle from installed
  sources and binds its hash to the image plan. BIOS/UEFI guests verify and
  regenerate it before libc recovery and after reboot. Altered bundle/source
  disk fixtures fail the documentation boot stage. Text remains roff source.

- [x] Build pinned i686 and x86_64 musl-static BusyBox as native packages and test their
  installed shell in a chroot without dynamic libc directories. Build logs,
  source/config/artifact hashes and upstream license files are retained.
  This bootstrap profile does not supply static holypkg or network recovery.
- [x] Link the prototype holypkg with musl-static dependencies; verify native
  archive, ELF, repository, solver and HTTPS fixtures. Run local package
  cache/install/check/remove and BusyBox shell probes inside a libc-free chroot.
  The separate dual-libc chroot gate now restores actual runtime payloads;
  i686 BIOS recovery is covered by the dual-libc image gate below.
- [x] Test the static client's DNS and HTTPS path in a private-network libc-free
  chroot, including wrong CA/digest refusals and a hashed JSON report. Pinned
  static BusyBox packages for i686 and x86_64 now include ip, udhcpc and
  nslookup; the fixture raises loopback with that packaged ip applet inside the
  libc-free chroot. Guest DNS is covered by the QEMU fixture below; public CA
  packaging remains a separate gate.
- [x] Package statically linked BusyBox, dinit, mdevd and the local recovery
  chain, plus both dynamic libc runtimes for i686 and x86_64. The isolated QEMU
  HTTPS recovery fixture is listed below; ordinary network configuration and
  public CA packaging remain unfinished.
- [x] Build pinned i686 and x86_64 musl as native runtime packages with source hashes,
  license and a natively linked loader SONAME. Run pthread/allocation probes
  alongside glibc.
- [x] Run musl32 and musl64 pthread/clock probes and bidirectional pipes in a
  shared disposable x86_64 root. A static i686 client installs both architecture
  slots with artifact-scoped decisions and restores either or both removed
  runtimes from its cache. The i686 BIOS boot gate is listed below.
- [x] Build pinned i686 and x86_64 glibc 2.42 loader/libc payloads from source as a native
  bootstrap package with licenses and recorded private-path patches. Complete
  SDK, auxiliary libraries, locale/NSS packaging and upstream-suite acceptance remain open.
- [x] Install and run glibc32, glibc64, musl32 and musl64 together on an x86_64
  kernel, including pthread/clock and pipes between ABI variants. Restore all
  four runtime packages through the static i686 client and cached artifacts.
  Glibc compilation uses the host multilib SDK; the packaged SDK is unfinished.
- [x] Run static holypkg inside an x86_64 root after deleting both glibc and musl
  runtime payloads; restore from cached LZ4 .holy files and run both dynamic probes.
  Repeat each libc separately, including loader symlink restoration. This gate
  covers missing payload repair, not forced package removal, boot or network recovery.
- [x] Build pinned i686 and x86_64 musl-static dinit with upstream tests; exercise
  service start/status/shutdown and stop-command effects with dinitctl in a
  libc-free chroot as an ordinary user. Install/check/remove the complete package,
  including command and man-page symlinks, through the transaction engine.
  The static-core image also exercises dinit as PID 1.
- [x] Build pinned i686 and x86_64 musl-static mdevd/skalibs with licenses and upstream
  HTML docs. Install, check and remove the package; parse valid symbolic-owner
  configuration and reject invalid regex inside a libc-free chroot with a
  private network namespace. The static-core image exercises readiness, coldplug
  and dinit integration; client libudev compatibility remains separate.
- [x] Build an x86_64 static-core ISO through native package transactions, a
  private dracut sysroot and Limine. Audit initramfs payloads against the installed
  root and reject dynamic ELF. Boot with dinit as PID 1, BusyBox, mdevd/coldplug
  and a local package install/check/remove in QEMU.
- [x] Extend that RAM profile with both dynamic libc packages and separate
  C probes. Boot present, glibc-missing, musl-missing and both-missing images
  under BIOS/TCG and UEFI/TCG. Restore absent payloads and loader links from
  cached .holy files inside the guest, verify broken-provider diagnostics,
  run allocation/thread/clock probes and pipe data between the two ABIs.
  The image audit rejects unexpected ldconfig aliases and undeclared dynamic
  ELF. Interactive on-disk installation remains open.
- [x] Mount an ext4 root through static holy-init/BusyBox switch_root. Boot
  present, glibc-missing, musl-missing and both-missing disk fixtures with
  BIOS/TCG and UEFI/TCG. Restore libc, sync, reboot and repeat the full boot,
  dynamic/IPC and package contracts on the same qcow2 overlay. Separate boot
  marker sets prevent first-boot evidence from satisfying the second boot.
  Verify the read-only raw base remains unchanged; a missing disk fails with
  a device timeout instead of falling back to RAM. This is an ISO booting a
  prepared ext4 image, not an installed disk with its own Limine/ESP.
- [x] Build a standalone GPT disk with a BIOS Boot partition, FAT32 ESP and
  ext4 root. Boot through Limine without a CD-ROM in BIOS/TCG and UEFI/TCG:
  present and both-libcs-missing cases each pass two complete boots, including
  cache repair, dynamic/IPC and package probes. The raw base remains unchanged.
  Kernel-update integration and holyinstall remain open.
- [x] Mount the GPT ESP at /boot before starting dinit. BIOS/UEFI recovery
  runs each pass two boots with both libc payloads initially missing; the
  guest checks the mounted kernel manifest and a FAT write across reboot.
- [ ] Resolve the glibc 2.42 upstream-check failures on the current host.
  The completed run has 6995 PASS, 4 FAIL, 89 UNSUPPORTED, 13 XFAIL and
  7 XPASS. Failures concern mount-header redefinition, two invalid-I/O-flag
  tests and rseq registration-length assumptions. Boot recovery proofs do
  not establish a passing upstream suite.
- [ ] Package Limine, dracut, kernel, firmware, SDK/sysroots and the default
  ConnMan+iwd network profile. Static local recovery and a private HTTPS
  recovery fixture have acceptance tests; production network recovery remains.
- [ ] Complete C99 `holyinstall` plans for accounts, network, encryption and
  filesystem choices. The implemented blank-disk GPT/ext4/FAT path uses
  reviewed plans and `holypkg --root`; account login has a VM fixture.
  Config and text menu now bind selected artifacts to registered source IDs
  through frozen plan format 4 and retain that provenance at install.
- [ ] Implement `holygetiso` with explicit inputs, installed man bundle and a
  boot-validated ISO for each target architecture. The first in-tree C99
  frontend now parses a single explicit local-input config, records its hash
  in the boot plan and drives the existing bootstrap/QEMU path. Additional
  relative includes now contribute to one frozen effective config; include
  cycles and duplicate scalar values fail before the build.
  local .holy packages join its set plan and input record.
  Pinned holy-http sources now solve and fetch same-catalog dependency closures,
  register their source IDs in the image root and bind each fetched artifact
  in the set plan.
  An explicit sealed mirror supplies the same pinned generation offline. The
  builder includes a full verified catalog in the image root only with
  embed-mirror yes. That binding uses a root-relative path, so moving the
  built root preserves source lookups without forcing every ISO to carry an
  entire repository.
  `--export-inputs` now checks the build's input lock, then copies and verifies
  package inputs, mirrors and plans separately. The builder records direct host
  tool paths and hashes, but does not archive their dependency closure. Cross-source dependency
  selection and relocatable installation remain
  open. The explicit build-only path records untested and exits 6. No image
  was built from this frontend without local package and kernel inputs.

## Acceptance gates

- [x] Validate the x86_64 ext4 recovery matrix across present/glibc/musl/both
  initial states and BIOS/UEFI under TCG: eight cases, sixteen boots. The
  retained-evidence gate checks per-boot identity, restoration and package/IPC
  probes, hashes input snapshots and rejects incomplete or duplicate cases.
  This matrix uses an ISO kernel and persistent disposable root overlays.

- [x] Run current prototype fixtures under GCC, TCC and Clang ASan/UBSan.
- [x] Boot the i686 static core with kernel 7.2.7, BusyBox, dinit, mdevd and
  static holypkg from a BIOS optical ISO under QEMU/TCG. The guest checks PID 1,
  man bundle, device permissions and a local package transaction. The dual-libc
  disk boot gate is listed below.
- [x] Boot an i686 BIOS dual-libc RAM ISO under QEMU/TCG with glibc and musl
  payloads absent at startup. The guest checks broken providers, restores both
  packages from cached native artifacts and runs C probes plus bidirectional
  pipes. The same fixture also checks a local package transaction. Separate
  present, glibc-only and musl-only initial-state runs are recorded in the
  build reports.
- [x] Boot an i686 BIOS ISO with a persistent ext4 root under QEMU/TCG. With
  both libc payloads absent, the guest restores them from cached artifacts,
  reboots and verifies the restored libraries, package state and IPC probes.
  The present/glibc-only/musl-only ext4 cases use the same two-boot contract.
- [x] Boot an i686 BIOS GPT disk independently under QEMU/TCG. The guest mounts
  its FAT boot partition, restores both libc packages, writes a boot-partition
  witness and verifies that witness plus package state after reboot. i686 UEFI
  and the interactive installer remain separate acceptance gates.
- [x] Install the i686 static core from a BIOS live ISO onto a disposable GPT
  disk under QEMU/TCG. The guest formats FAT32 and ext4, applies the reviewed
  package set, creates a login account and boots the installed disk separately.
  The second guest checks dinit, holypkg, authenticated login and doas. The
  account menu, PAM/NSS, network and i686 UEFI remain untested by this gate.
- [x] Boot a dual-libc RAM image with both libc archives absent from its cache
  and fetch their native artifacts over HTTPS from a QEMU fixture in a private
  network namespace. The guest uses static BusyBox ip and holypkg, verifies the
  fixture CA and artifact hashes, repairs both runtimes and runs dynamic/IPC
  probes. Guest DNS resolution and hostname-verified HTTPS are covered for both
  architectures; public CA and external network coverage remain open.
- [x] On persistent ext4 QEMU roots, remove both dynamic libc packages through
  holypkg with an explicit broken-dependency decision, reboot into the static
  core, then reinstall both native artifacts from cache. Check broken-provider
  diagnostics, package state and dynamic/IPC probes after the second boot on
  x86_64 and i686. The i686 BIOS GPT case also boots independently from its
  FAT ESP and passes the same two-boot contract.
- [x] Run `make check-root` against disposable target-root install, check,
  remove and recovery fixtures; this gate does not boot a system.
- [x] Add a BIOS/UEFI `make check-qemu ARCH=... ISO=... BOOT_PLAN=...` runner
  with serial markers, ISO hash, QEMU argv, exit status, elapsed time and logs.
  Missing images return a requirement error; blank ISO fails both architecture
  fixtures via `make check-qemu-gate`. Cancellation reaps the guest and records
  failure. The x86_64 static-core ISO passes BIOS/TCG and UEFI/TCG boot contracts.
- [x] Run `make check-install` against plan/apply/disk fixtures and a separate
  installed-disk VM gate in BIOS and UEFI. The VM gate covers disk preparation,
  installation, boot and account login.
- [x] Add `make check-hardware` for a physical NVIDIA GPU bound to Nouveau:
  identify Mesa NVK, present Vulkan frames and measure accelerated OpenGL
  frames. Save commands, output and timings in a JSON report. A host-only
  diagnostic pass is labeled as such; the default Holy gate returns 6 without
  an installed Holy database. The present host probe passed on Slackware;
  no Holy hardware result is claimed.
- [ ] Extend the QEMU runner to qcow2 trial overlays and per-probe
  timeouts/result channels. The runner now accepts self-contained raw and
  qcow2 input disks, copies either to a read-only base and boots a separate
  qcow2 overlay. Guest stage markers get independent configurable deadlines
  and per-stage reports. Live input copy consistency remains unverified;
  full `holypkg test PLAN` integration and the Holy hardware gate remain open.
- [ ] Boot both target architectures in QEMU and prove PID 1, shell, package
  install/removal and recovery after removing either or both dynamic libc runtimes.
- [ ] Run compiler/SDK, language, GUI, graphics, gaming, workstation and foreign
  source cases with pinned artifacts, logs, elapsed time and explicit coverage.
