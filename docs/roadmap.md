# Holy roadmap

## Current state

- [x] Run C99 `holygetiso` from an explicit config through a real x86_64
  dual-libc ext4 build. Its ISO passed two QEMU boots with libc removal and
  cache recovery. A second build selected a noarch package from a pinned,
  sealed native mirror, installed it with its source ID, embedded the mirror,
  and passed the same two-boot contract. Both `--export-inputs` bundles passed
  SHA-256 verification. Portable host-tool export remains open.
- [x] Stage an exact package when its native catalog cannot close a dependency,
  then resolve it with an explicitly added package from another pinned source
  in holyinstall's frozen set plan. A fixture rejects the root alone, installs
  both artifacts with their separate source IDs, and checks the installed DB.
  A full x86_64 ext4 image with two sealed source mirrors passed two QEMU boots;
  its exported input bundle passed SHA-256 verification.
- [x] Prepare additional image packages with the native `holypkg add` resolver
  in a separate root bound to all pinned mirrors. The image builder copies its
  selected artifacts with their source IDs, including a unique exact provider
  from another source. A two-source fixture installs the result with
  `holyinstall`; no package is installed in the resolver root. A real x86_64
  ext4 ISO with only `add fixture:cross-root` selected `other:helper`, passed
  two QEMU/TCG boots with both libc runtimes removed and restored, and its
  exported inputs passed SHA-256 verification. Pinned resolver answers now
  select a source by consumer hash and requirement ID when two catalogs offer
  the same provider. A three-source fixture rejects the unanswered choice;
  a second full ISO with the pinned answer passed two QEMU/TCG boots and its
  exported inputs passed SHA-256 verification.
- [x] Fetch pinned bootstrap inputs over HTTPS into an explicit directory,
  verify SHA-256 before publication, and reject altered cached files. On
  x86_64, local builds produced musl 1.2.5, static BusyBox 1.37.0,
  static dinit 0.22.1 and static mdevd 0.1.8.2 packages. BusyBox, dinit
  and mdevd passed their libc-free chroot fixtures. The complete static-deps
  source set built musl-static holypkg, holyinstall, holygetiso and holy-init.
  Static core, foreign archive import, and local recovery after removal of
  both dynamic libc passed their chroot fixtures. A 7.2.7 x86_64 static-core
  ISO booted under QEMU/TCG and passed its PID 1, shell, package and installer
  probes. A second x86_64 ISO with glibc 2.42 and musl 1.2.5 passed QEMU
  boot and in-guest libc-recovery probes after both runtimes were removed.
  A persistent ext4 variant passed two QEMU boots, including removal of both
  libc packages and recovery across reboot. These local artifacts remain
  under out/; i686 boot and a published image remain separate gates.
- [x] Build i686 musl, glibc, BusyBox, dinit, mdevd and the musl-static Holy
  binaries. The i686 static client passed the pentium2 QEMU user-mode target
  test and the libc-free static-core chroot fixture. BusyBox, dinit and mdevd
  passed their package fixtures. A single x86_64 root ran glibc32, musl32,
  glibc64 and musl64 probes with threads, pipes and local recovery. i686
  kernel boot is still untested in this local build.
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
  prereleases. APK and XBPS comparators now also select prepared updates in
  their own source slots; remaining foreign comparators remain open.

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
  a file provider in its fetch receipt. Common sync/search/info/fetch now use
  the registered APT binding with explicit suite, component and index
  architecture. An inverted index, automatic candidate
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
  package hash and signature, and records the selected index hash and artifact URL in
  output origin. Optional exact SONAME and file requirements check converted
  payload claims before the fetch receipt becomes complete. The signed HTTPS fixture
  installs, checks and removes an associated output in a disposable root.
  `apk providers soname:NAME` searches a digest-bound inverted index of so:
  claims as hints; the
  checked import still decides whether a package really provides the SONAME.
  `apk fetch-provider` now chooses a unique candidate by SONAME and architecture,
  verifies its payload, and returns decision-required when the index lists
  multiple candidates. The general resolver does not invoke this path yet.
  A native `add SOURCE:PACKAGE` can take `--candidate-local ALIAS=FILE.holy`
  for an explicitly associated imported output. The shared set resolver and
  installed graph check it alongside native packages; automatic foreign
  candidate discovery remains open.
  Native automatic provider search now skips active foreign source families
  instead of counting their absent native mirror as unavailable.
  The common search/info CLI reads bound APK repositories by source alias and
  optional repo name; APK file coverage still reports unavailable.
  The common fetch CLI now selects a bound APK artifact by source, version,
  architecture and repository, with package verification and optional import.
  The common sync CLI accepts APK sources and a named repository, using the
  registered signing key and the APK index verifier.
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
- [x] Accept nonempty HOLY/transform as an immutable provenance record in local
  solve, single-package planning, set installation and removal. The installer
  verifies the already transformed payload and does not execute the record.
  A pacman fixture splits one foreign archive into noarch, x86 and x86_64
  outputs, installs all three in one set, checks them and runs both static ELF
  programs. Cached update with a transform record also passes. Executable
  hooks and unresolved foreign semantics remain decision gates.
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
  A consumer that states no runpath is searched in the loader default for its
  machine, /lib64, /usr/lib64, /lib and /usr/lib for x86_64 and /lib and /usr/lib
  for every other machine, so a provider that keeps the name outside every
  searched directory is refused with unknown-loader-search and the searched list
  is named. A provider-owned symlink chain to a versioned library is accepted. Cached
  replacements revalidate every selected SONAME edge. Installed check reads
  verified target-root ELF files and reports provider, alias or earlier-path
  shadowing drift, resolving the loader default the same way. A searched directory
  that already holds the name is shadowing unless the opened path is the
  provider's own file, which a merged-/usr directory link such as /lib64 to
  usr/lib64 leaves unchanged, so the planner and installed check compare the
  opened inode rather than a manifest path. Other loader tokens,
  cross-package aliases and plugins remain open.
- [x] Resolve direct absolute shebangs in native package sets against exact
  executable ELF paths. Save the selected provider edge, reject unresolved
  env/malformed scripts, block removal of a needed interpreter, and report
  installed interpreter drift. Resolve relative symlink chains in the supplied
  candidate set and protect each selected alias provider. Discover installed
  alias owners for a later script installation using root-confined lookup,
  including chains split between installed and new packages.
- [ ] Handle hooks, service consent, overrides, general rollback and
  recovery of each interrupted mutation phase. `holypkg override list` now
  reads the user override store of a target root and reports every record
  against the installed set. A record is the fixed line order
  holy-override-1 form: a scope naming one artifact digest, one package
  version or one package with its later versions, an absolute path,
  optional arch and libc conditions, the digest of the packaged file, the
  digest of the patch body in the same file and the digest the patched file
  has to carry. The owner of the path comes from the installed manifests
  and the file is read through the root, so a record never claims an
  artifact by its own word. Each record reports applied, pending,
  not-installed, review, unreadable or invalid; one review is 3 and one
  invalid record is 2, and --json uses holy-override-report-1. A fixture
  covers all six states, a scope naming another artifact, a body that is
  not the recorded patch, a store entry that is not a regular file, a file
  that cannot be read through the root and a root with no database.
  A set plan states the records it would write over and binds them into the plan
  hash, so a store that changed between the plan and the apply is status 3 instead
  of a silent overwrite; the read takes no database lock, so a plan and its apply
  compare the same store. An update plan states the records its own file plan writes
  in an [overrides] section the plan digest covers, so a store that changed between
  plan-update and apply-update is status 3 instead of a silent overwrite of a patched
  file; the update fixture checks the section, that the plan is stable while the
  store is, that a record added in between is refused, and that the plan without the
  store is the plan the fixture recorded. The report states the form of each
  record: a body that is the whole replacement file carries one digest for
  patch and result and is a whole-file record, while two different digests
  make it diff shaped, which this format does not describe and this manager
  will not guess at. `holypkg override plan NAME` prepares one record: it
  resolves the artifact that owns the path, refuses a record whose installed
  payload file drifted, a record whose result is already in place and a file
  that is not what the record applies to, then states what applying it would
  write with a SHA-256 over the record, the owner, both digests and the
  identity of the target root with its installed generation. Applying that
  plan and re-applying a record on a later version are still open, as do
  service consent, general rollback and per-phase recovery.
- [x] Carry config/mutable flags through verified manifests and installed checks;
  import Debian conffiles as config files, reject invalid declarations, and
  report changed-config.
- [x] Preserve edited config files during a cached update. Bind the observed
  hash to the reviewed plan, publish incoming bytes as an owned .holy-new,
  store the raw and local manifests separately, and carry local state through
  later updates. The fixture checks stale plans, repeat updates, ownership,
  recovery after interruption, reverse cached update and package removal.
  Missing-only repair restores PATH.holy-new from the verified archive and
  rejects a missing preserved public config, whose local bytes are absent from
  the archive. Explicit config replacement remains open.
- [x] Accept an artifact-scoped skip decision for nonempty HOLY/hooks in local
  set installation. Print hook records before the decision, bind the skip to
  plan and journal, retain hooks/transform in installed state, report
  skipped-hook as installed-unconfigured, and cover add/check/remove fixtures.
  Native postinstall execution is covered below. Editing hooks and handling
  foreign phases or unknown external effects without explicit retry remain open.
- [x] Review and run native postinstall scripts from installed packages in the
  target root with an interpreter named by the hook record. A separate plan
  binds root, generation, artifact and script bytes; a persisted journal
  records running/ready stages. An unknown result needs an explicit retry,
  and a user-namespace fixture covers failure, recovery and success. Foreign
  scripts, preinstall and automatic execution during add remain open.
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
  provider update. Hooks and content merging remain open.
- [x] Preview and apply a reverse cached replacement from a committed update
  transaction with `holypkg rollback`. Verify the original journal, committed
  marker and plan digest; reuse the dependency solver, whole-file plan hash,
  writer lock and update recovery. External hook effects and arbitrary
  transaction types remain outside this command.
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
  It probes installed providers first, including inactive origins. Same-source
  registered-parent and source-family preference now choose among exact native
  offers by source-id and policy; source priority breaks ties within a rank.
  Explicit answers override them. Source plan now reports changes to trust,
  key, parent, family and priority; source show displays the applied policy.
  Complete coverage diagnostics and plugin
  discovery remain open. A
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
  Generation 8 records and verifies the version comparator family. Update
  preparation selects from index records and stages only the chosen artifact;
  the fixture corrupts an unselected same-slot archive without changing the
  chosen update.
  Large-catalog index scaling remains open.
- [x] Bind a verified synced mirror and index digest to a registered source-id
  under the target database lock. `cache list` now also reports the reverse fact a
  cache walk cannot see: every installed artifact whose cached object is absent,
  named with its package name and the no-cached-object reason, followed by a
  generation, cached, unavailable and unretained summary, so a cache requirement
  is visible before a plan needs it. A retained object that a transaction record
  refers to now carries reason transaction-reference, and one whose transaction tree
  is too deep to inspect carries reason unverified-transactions, so the provenance
  cache clean checks is visible without failing a whole-cache inventory. The walk
  rewinds the shared directory offset, since a repeated walk over one descriptor
  would otherwise see an exhausted stream. Resolve add, fetch, search and info without
  repeating --catalog; reject corrupt bindings and changed mirrors. Keep the
  binding across alias renames. Sync without --output now publishes a verified
  generation in the target cache and binds it for source queries. A registered
  Ed25519 key now rejects unsigned or changed bound catalogs. A rootless
  system-cache workflow remains open.
- [ ] Implement remaining foreign binary adapters and file indexes with real
  fixtures: RPM, eopkg, homebrew and guix, all of which now have one. APT has a
  pinned local index
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
  survive moving a target root with its cache.
  Common sync/search/info/fetch now use the same registered-source checks for
  XBPS, with explicit index architecture and version where required.
  A separate digest-checked
  shlib-provides index now gives exact SONAME candidate hints from Void metadata,
  including source-bound queries. Foreign binary import now derives SONAME
  provides from classified ELF payloads, so a selected archive can supply
  separate file-level evidence. Complex patterns remain review-required.
  `holypkg key add|list|show|remove` now enrolls a public key under a name in
  the target root, records the digest the enrollment saw and refuses a key whose
  stored bytes changed, so one key file backs several sources and a changed key is
  not trusted. A source public-key value with no slash and a usable key name is an
  enrolled name, and the frozen source record is the same digest the path
  produces. The git-source fixture enrolls the fixture key, plans and syncs the
  source by name, and covers an unknown name, a traversing name, a file that is
  not a key, a tampered enrollment, an unconfirmed removal and a replacement
  decision. An enrolled RSA keyring still names a file for every command that
  verifies with it, since the apk, apt and xbps readers take a path;
  automatic provider selection remains open.
  `holypkg index` now answers the two questions the planner answers internally: it
  names the installed artifacts that own a path and the artifacts that declare a
  capability, and it prints the whole index when given no selector. A name with
  several providers is a candidate list and the status is 1, since choosing one of
  them is a decision a report does not make, and a name nothing declares is status 6
  because an absent answer is not a proof. A fixture installs an application, the
  library it chose and a second provider of the same soname that places its file
  elsewhere, then checks one owner, two candidates, the agreement with the conflict
  report and every refusal. The planner still reads the manifests themselves, so an
  index narrows nothing yet.
  A Homebrew formula converter now reads a formula as Ruby text and never evaluates
  it. The class name, description, homepage, license, url, sha256 and revision are
  carried, a formula that states no version records the version its source url
  carries, a depends_on becomes a runtime requirement and a :build dependency a build
  requirement, and a recommended or optional dependency is reported. A resource or a
  patch block with a pinned url and digest becomes a fetched source. A system call
  inside def install or on_linux becomes a build step that runs the same command in
  the source root, with #{prefix}, HOMEBREW_PREFIX, #{libexec}, #{etc}, #{var} and
  #{buildpath} rewritten onto the build root; an interpolation the reader does not
  model keeps its text and is named. Every other statement of an install body stays
  Ruby, so the formula is copied beside the recipe as homebrew-install.rb, the build
  declares a ruby build requirement, and the report names the file and line of each
  statement. A fixture converts a mechanical formula, builds the recipe it produced
  into a real package, installs it beside a provider that closes the requirement the
  depends_on created, and converts a formula full of Ruby, platform blocks, a bottle
  and a test block, checking every named refusal. The build also keeps the mode a
  declared directory had, since a package built here used to claim /usr with the mode
  of the manager's own staging tree and could not be installed beside any other
  package that claims it.
  A Solus eopkg importer now reads the ZIP artifact, carries the metadata as text and
  walks the install tar with libarchive. The metadata is read in its own context, so a
  packager identity is not a package name and a build dependency is not a runtime
  requirement; a description, a history entry, a conflict, a replacement and a
  declared capability are counted and named rather than imported. Each runtime
  dependency becomes one exact package requirement whose original field is the
  releaseFrom value the metadata states. The install tar travels whole under a private
  path, since a Solus layout is recorded rather than claimed, and an install script, a
  COMAR object, a delta and a signature are dropped rather than run or trusted.
  A Guix package definition converter now reads the definition as Scheme text and
  never evaluates it. The name, version, synopsis, homepage, license and build system
  are carried, an origin becomes one pinned source with the base32 digest decoded into
  the hex a Holy source records, and an origin that is not a url-fetch is reported.
  Each name in inputs becomes a runtime requirement and each name in native-inputs a
  build requirement, where a versioned entry contributes only its name. The build
  system becomes the tools it runs: gnu-build-system becomes autoreconf, configure
  with the payload prefix, make and make install, and cmake and meson become their
  three commands, while a system this reader does not replace is reported. An
  argument whose entries are literal strings becomes the flags of the phase that takes
  them, and an argument that computes a value keeps its text and is reported. A
  fixture converts a mechanical definition, builds the recipe it produced into a real
  package, and converts a definition with a git origin, a trivial build system, a
  versioned input, a phase list, a computed flag and a modulo expression, checking
  every named refusal.
- [ ] Implement AUR, Aports, xbps-src, SlackBuilds, RPM spec, Debian source,
  Gentoo, Pacstall, Homebrew and Guix recipe conversion with helper environments
  and split outputs. Every named family now has a converter.
  The native side of that work now exists: `holypkg build` parses a
  holy-recipe(5) manifest, fetches pinned sources, unpacks them, runs reviewed
  phase steps with absolute HOLY_* paths, and packs one .holy per declared
  output. Outputs are grouped by the ABI facts of the payload, so a single
  build yields a noarch/nolibc document output and separate ABI libraries.
  Requirements come from declared depend records and payload DT_NEEDED entries;
  provides come from payload SONAMEs; config flags and runtime hooks are
  recorded with the produced digests. `split-step` gives one output its own
  staging tree, so a payload requirement and a hook script are written only into
  the output that carries their file. The PKGBUILD family converts: identity,
  dependencies with their comparison relations, source entries with their
  sha256sums, backup paths and install fragments are carried; the phase bodies
  keep their Bash with the makepkg variables mapped onto the exported paths;
  each package_NAME function becomes a split output; and a conversion report
  lists every carried, preserved, helper, unknown and changed item with its
  PKGBUILD line range. A fixture converts a real PKGBUILD, builds the produced
  recipe through the normal engine and installs its split outputs.
  The converter also reads lists the way a shell does, so a comma inside an
  element belongs to its name, and a brace inside a parameter expansion does
  not end a function body.
  The Void template family converts as well: `holypkg convert template` and
  `holypkg import --format void` read the xbps-src template, carry its identity,
  dependency lists with their comparators, distfiles with their checksums and
  conf_files/mutable_files, and keep every pre/do/post phase body in Bash behind
  a prologue that maps $wrksrc, $masterdir, $DESTDIR and $PKGDESTDIR onto the
  exported HOLY_* paths. The v* helpers a body calls are carried into that
  prologue, and vman, vsv, vsed, vcompletion and vsrccopy are reported as
  unresolved. A NAME_package function becomes an output whose split step
  carries its pkg_install body. A patches or files directory is archived
  beside the recipe, an INSTALL or REMOVE file becomes one hook, build_options
  are fixed to build_options_default so no vopt_ call survives, and a phase the
  template leaves out is reported as supplied by the build style the converter
  does not run. A fixture converts a template with three outputs, builds it
  through the normal engine and checks the resulting ABI groups; 700 upstream
  templates from void-packages convert and every produced recipe passes the
  manager's own validation.
  The Aports family converts as well: `holypkg convert APKBUILD` and
  `holypkg import --format aports` read the APKBUILD, carry its identity, map
  arch onto the Holy machine names, and read depends as depend and
  makedepends/makedepends_build/makedepends_host/checkdepends as build-depend,
  so a !NAME conflict becomes x-conflicts and a so: or cmd: requirement is
  reported. The abuild phase bodies keep their original shell behind a prologue
  that maps $srcdir, $startdir, $pkgdir, $subpkgdir, $JOBS and the other
  abuild.conf parallel settings onto the exported HOLY_* paths, and the step
  changes into $builddir because abuild runs a phase there, with a declared
  builddir rebased on the source tree and an absent one reported as the abuild
  default of $srcdir/$pkgname-$pkgver. Each subpackages entry becomes an output
  whose split step carries its split function, taken from the entry or from the
  last dash-separated suffix of the name, and an entry with no written function
  is reported as needing the default_dev, default_doc, default_static,
  default_openrc or default_libs helper, so no output is claimed for it. A
  post-install or pre-deinstall script becomes one hook, and the other four
  install actions are reported as having no Holy hook stage. Since aports pins
  sha512sums, which a Holy source cannot use, a remote source with no sha256sums
  entry is reported rather than fetched, while a local source beside the
  APKBUILD is copied next to the recipe and hashed as SHA-256. The shell text
  the Void and Aports converters share now also lives in one parser, so a
  conditional block, a case block, an appended value and an unreadable top level
  statement are handled the same way in both. A fixture converts an APKBUILD
  with four declared subpackages, builds the produced recipe through the normal
  engine and checks the resulting split payloads and hook; all 1668 upstream
  APKBUILDs from aports convert and every produced recipe passes the manager's
  own validation.
  The SlackBuilds family converts as well, and needs a different shape because a
  SlackBuild script is one linear shell program rather than a set of phase
  functions. `holypkg convert NAME.SlackBuild` and
  `holypkg import --format slackbuild` read the script, carry PRGNAM, VERSION,
  BUILD, TAG and PKGTYPE in either the plain or the ${NAME:-value} form, and put
  the whole body into a single build step whose prologue maps $ARCH onto
  $HOLY_ARCH, $CWD and $TMP onto $HOLY_SRC, $PKG onto $HOLY_DEST and $OUTPUT onto
  $HOLY_OUT. The cd $PKG and the /sbin/makepkg call are left out because the
  engine packs the payload, and so is a tar line reading $CWD, because the engine
  has already unpacked the recorded archive. slack-desc beside the script carries
  the summary, homepage, requires and conflicts, and the info file carries the
  upstream URL and its MD5 sum, which is reported as unusable; a local archive is
  copied next to the recipe and hashed as SHA-256 instead, and every other file
  the script reads through $CWD travels beside it as a source. A doinst.sh becomes
  one hook, the $PKG/install tree is reported as packaging metadata, and the strip
  pass, the ownership rewrite, the user and group creation and the loader and
  desktop cache helpers are reported as unresolved. A fixture converts a script
  with a local archive, a patch and an install hook, builds the produced recipe
  through the normal engine and checks both the ELF group and the noarch group;
  all 2211 upstream scripts from the development and libraries trees convert and
  every produced recipe passes the manager's own validation.
  The RPM spec family converts as well, and needs a parser of its own because a
  spec is neither shell nor a list of phase functions. `holypkg convert NAME.spec`
  and `holypkg import --format rpmspec` read the spec, carry Name, Version,
  Release, Summary, License and URL, collect the %global and %define records and
  expand the macros that resolve, so a body keeps its own words with _sourcedir,
  _builddir, _topdir and buildroot rewritten onto the exported paths. A Version
  or Release written with a macro in it keeps only its literal part and reports
  the macro, so the value stays what the spec says. BuildRequires becomes
  build-depend and Requires becomes depend, read one record per line because an
  rpm requirement carries its comparison with it; Provides, Conflicts,
  Obsoletes and Recommends become x- records, since none of them is a
  requirement, and a rich dependency, an rpmlib capability and a requirement
  naming a file are reported. The prep, build, install and check sections become
  the matching phases, %setup, %autosetup and %autopatch become a cd into the
  unpacked tree and a patch pass over the declared patches, the %make_install
  family and the __ prefixed helpers become the shell line they stand for, and
  every other rpm section command is reported and left in the body so the build
  fails visibly rather than losing a step. A %package block becomes an output
  whose split step copies the paths its own %files list named out of the main
  tree, because an rpm subpackage is a file list and not a body; the main
  %files list is reported as a check the install already made. A local Source
  or Patch file beside the spec is copied and hashed as SHA-256, and one that is
  absent is reported, since a spec normally pins no digest. A fixture converts a
  spec with a subpackage, a patch, a file requirement and a rich dependency,
  builds the produced recipe through the normal engine and checks the three
  payloads it produced; 387 of the 388 source RPM specs sampled from the Fedora
  archive convert, the one refusal being a spec with no Name at all, and every
  produced recipe passes the manager's own validation.
  The Debian source family converts as well, and needs a parser of its own
  because a source package is a set of files rather than one program text.
  `holypkg convert debian` and `holypkg import --format debian` read
  debian/control, which is RFC822 with continuation lines, and take the version
  from the first record of debian/changelog, since that is the distribution
  version and not the upstream one. It is split at the last dash: an all-numeric
  tail is the Debian revision and becomes the Holy release, a version with no
  such tail is native and gets release one, and either outcome is reported, as
  is an epoch, which names a packaging revision order and is dropped. A
  relationship field is a comma separated list of groups and a group may offer
  alternatives with a pipe, so the first alternative of each group is carried
  and the rest are reported; Build-Depends and Build-Depends-Indep become
  build-depend, Depends and Pre-Depends become depend, a strict comparison
  becomes lt or gt, and Provides, Breaks, Conflicts, Replaces, Recommends,
  Suggests and Enhances become x- records, since none of them is a requirement.
  A dpkg substitution variable such as ${misc:Depends} is reported rather than
  guessed, and an entry with an architecture qualifier is reported instead of
  being turned into a record. Each binary stanza becomes an output, and a binary
  that names a .install, .docs, .manpages or .links file list becomes a
  subpackage whose split step copies the paths that list named out of the main
  tree, because a debian subpackage is a file list and not a body; a list line
  is a source and a destination, and a line with no destination names the source
  itself, while a list that names no path at all is reported rather than written
  as a split step that would fill no tree. The binary that names no file list
  owns the whole tree, and more than one such binary is reported since the
  converter cannot tell which one is the main tree. debian/rules becomes the
  build step behind a prologue that sets DEB_HOST_MULTIARCH and
  DEB_BUILD_OPTIONS; dh is a macro framework rather than a script, so every
  debhelper call, every debhelper override and dpkg-buildpackage are reported and
  left in the body so the build fails visibly. The maintainer scripts,
  debian/copyright, debian/watch and debian/source/format are copied next to the
  recipe and reported, and a lintian-overrides file is reported as suppressing a
  report rather than building anything. A fixture converts a package with a
  subpackage file list, a maintainer script, an alternative and a build
  profile, and checks the split payloads, the version split and the malformed
  and empty cases; all 398 source packages sampled from the Debian trixie
  archive convert and every produced recipe passes the manager's own validation.
  The Gentoo ebuild family converts as well, and needs the shared shell parser
  rather than a parser of its own, because an ebuild is bash with a metadata
  header. `holypkg convert NAME.ebuild` and `holypkg import --format gentoo`
  read it, take the identity from the file name, which is PN-PV-rPR.ebuild, so a
  trailing -rN becomes the Holy release, a file name with no revision gets
  release one and an epoch is preserved and dropped. EAPI, LICENSE and SLOT are
  carried, and KEYWORDS names the machines an ebuild is tested on rather than
  the machine that builds it, so arch is any. A mirror:// entry names no single
  address and a remote archive has no digest, since a Gentoo Manifest pins a
  BLAKE2B and a SHA-512 rather than the SHA-256 a Holy source needs, so both
  are reported, while a PATCHES entry and any other file named beside the ebuild
  is copied next to the recipe and hashed as SHA-256. A dependency atom keeps
  its package name and its comparison, a blocker becomes x-conflicts, and a USE
  conditional, an any-of group, a slot, a use dependency and a virtual are
  reported, since a Holy recipe has no USE flags and cannot choose between the
  members of a group; the atoms inside one are carried anyway so the build
  still holds them. Each standard phase function becomes the matching phase
  behind a prologue that rebuilds the variables Portage exports onto the Holy
  paths, a phase the ebuild leaves out is the one the inherited eclasses supply,
  and every eclass and every ebuild.sh helper a body calls is reported rather
  than run, so the build fails visibly. A fixture converts an ebuild with two
  local patches, a blocker, an any-of group, a slot, a use dependency, a virtual
  and a maintainer script, and checks the patches, the split identity and the
  malformed cases; the parser work this needed fixes four gaps that a Void
  template and an APKBUILD could not reach, namely a trailing comment that
  holds an apostrophe, a line continuation that reads as an unterminated value,
  a heredoc whose body holds a brace, and a parenthesized list written one
  element per line, so 12191 of the 12192 ebuilds in the gentoo tree sampled
  convert, the one refusal being the package skeleton, which carries no version
  in its file name, and every produced recipe passes the manager's own
  validation.
  The Pacstall family converts as well, and needs the shared shell parser plus
  its own reading of a metadata header that is written as assignments.
  `holypkg convert NAME.pacscript` and `holypkg import --format pacstall` read
  the pacscript, carry pkgname, pkgver, pkgrel, pkgdesc, url, license,
  maintainer, repology, arch and gives, and expand $pkgname, ${pkgname},
  $pkgver, $pkgrel, $gives, $pkgbase and $epoch as well as a variable the same
  pacscript states in an assignment of its own, so a name or a version written
  from a private value of that file is carried; a value that needs the shell to
  choose a substring is a computed identity and returns 2. An epoch is
  preserved and dropped. amd64 and x86_64 become x86_64, i386 and i686 become
  i686, any and all become any, and a machine Holy does not carry is written as
  it stands and reported. A source entry is NAME::URL, ?NAME::URL or a plain
  URL, a sha256sums entry in the same order becomes source-sha256, and a file
  named beside the pacscript is copied next to the recipe and hashed; a git
  address, a remote source with no digest and a plain http address are reported
  rather than carried, since a Holy source is fetched over https. The engine
  fetches and unpacks the recorded sources, so the extracted tree takes the
  place of srcdir, which is reported. depends, makedepends and checkdepends
  become depend and build-depend with the comparator names the other converters
  use, a group of alternatives written with a pipe is reported with the first
  of them carried, and pacdeps become depend with the fact that they name
  packages of the same pacstall repository reported, because a Holy resolver has
  to find them in a source that has them. provides, conflicts, breaks,
  replaces, enhances, recommends and suggests name no requirement, so they
  become x- records, an optdepends entry becomes x-optdepend with its
  description, a backup entry becomes config and an r: prefix becomes config
  mutable with a report. A list written per machine or per distribution under a
  suffixed name is reported, and so is every setting that steers a Pacstall run
  and every digest list other than sha256sums. prepare, build, check and
  package keep their own shell behind a prologue that rebuilds pkgdir, pacdir,
  srcdir, startdir, builddir, TARCH, NCPU, pkgname, pkgbase, pkgver, pkgrel,
  pacname, gives and epoch from the exported Holy paths, and every helper a body
  calls and every variable of the Pacstall environment a body reads is reported
  rather than invented. A list of names with a pkgbase is a split pkgbase: every
  name becomes an output and its package_NAME function becomes the split step
  that fills it. pre_install, pre_upgrade, post_install and post_upgrade become
  one install hook and pre_remove and post_remove one remove hook, each written
  beside the recipe, declared as a source and installed into the payload, and a
  Holy hook runs with ACTION unset, so the pre and post bodies arrive in the
  order Pacstall calls them. A conditional block and an assignment inside one
  are reported, since the converter evaluates neither. A fixture converts a
  pacscript that builds through the normal engine, one that is a split pkgbase,
  one with both hook groups, and one that carries every reported case; 910 of
  the 919 upstream pacscripts from pacstall-programs convert and every produced
  recipe passes the manager's own validation, the nine refusals being seven
  versions that carry a tilde, which a recipe records as a label, and two names
  that need a shell substring expansion.
  The parser work this family needed fixes four gaps the Void, Aports, RPM,
  Debian and Gentoo families could not reach: a list written on one line was
  recorded as one value with its parens left in it, a list written on many
  lines had its elements and its closing paren read again as statements of
  their own, the line count drifted by one for every list, and a heredoc word
  written apart from its << was not recognized, so an apostrophe inside such a
  body ended the function early. An x- record of a recipe also undercounted its
  buffer, so a value with a byte outside printable ASCII overflowed it while the
  build read the recipe.
  The makepkg build environment and the vm build environment remain open.
  The build runner no longer loses its private build root, keeps a root the
  caller named, and reaches both the default and the named-root path in the
  fixture. The same run also restores three interrupted-mutation fixtures whose
  LD_PRELOAD shims hooked the wrong symbol names under _FILE_OFFSET_BITS=64, and
  restores the plan-set check that a source binding names an artifact inside the
  resolved set.
- [ ] Implement Nix closure, Flatpak, Snap, AppImage, Scoop and WinGet imports
  without silently discarding runtime requirements.
  AppImage type 2 inspect/extract now snapshots the original, checks ELF and
  SquashFS structure, extracts with unsquashfs without running the image, and
  records an unclassified AppDir plus per-file ELF, loader, script and link facts.
  `import --format appimage` now also emits one native package beside the review
  bundle: the AppDir travels whole under a private path, the entry point becomes a
  link under a private bin directory, /usr/bin/NAME is a launcher that starts it
  in the package run context, the desktop entry is rewritten onto the launcher,
  and the classification and conversion reports travel with the package.
  Dependencies are the payload's own: a DT_NEEDED the payload carries through its
  SONAME is satisfied privately, every other name becomes a soname requirement,
  and a link whose absolute or escaping target cannot travel in a payload
  becomes a recorded file requirement. The arch, libc and version come from the
  payload itself, a mixed-ABI payload is refused, and every entry is attributed to
  the installing user with each parent directory declared by the same manifest.
  The import returns decision-required and the package report names the changed
  launch conditions, the dropped image-level sandbox, the runtime probes static
  inspection cannot close, the path views a link needs and the version decision.
  `snap inspect` and `snap extract` now read the eight-byte header that states the
  SquashFS offset and size, extract with unsquashfs without running the image, and
  record the manifest beside per-file ELF, loader, script and link facts.
  `import --format snap` emits one native package: the snap root travels whole under
  a private path, the image itself is the entry point, /usr/bin/NAME is a launcher
  that starts it in the package run context, and the classification and conversion
  reports travel with the package. The name and version come from the manifest, the
  arch and libc from the payload's own ELF files, a mixed-ABI payload is refused, and
  the base the manifest names becomes a package requirement, since the runtime snapd
  would mount has to come from a source here; plugs, confinement, hooks,
  environment names and command-chain entries are recorded and counted rather than
  emulated. The import returns decision-required and the report names the base
  requirement and everything the conversion drops.
  The Flatpak manifest converter reads a JSON manifest, carries the id, version,
  summary, url, command, branch and machine, turns the sdk into a build
  requirement and the runtime into a runtime requirement because they are two
  different ids, and gives each module one step in module order. The make,
  autotools, autogen, cmake and meson templates are replaced by the shell that
  runs the same tools, a patch applies with -p1 before its module builds, an
  inline source becomes a file beside the recipe, a local archive is copied next
  to it and a remote one keeps its declared sha256, a /app path becomes $DESTDIR
  and a module prefix becomes /usr. finish-args permissions, cleanup steps and
  build extensions are dropped and counted, and a buildsystem with no Holy phase
  is a helper the report names.
  The Scoop importer reads a manifest as JSON, verifies the artifact beside it
  against the digest the manifest pins, and carries it whole under a private
  path, with the declared extract_dir replacing the first component of every
  archive member and the declared program looked up inside the payload. A
  bucket dependency becomes a package requirement, while the PowerShell
  installer, the Windows integration keys and the bucket update keys are
  dropped and counted. Nothing runs the artifact and no Wine requirement is
  invented, so the import returns decision-required.
  The closure fixture now proves the shape a Nix closure needs: one shared object
  package with two application packages that name it by exact path, one owner and
  several dependents. Removing an application leaves the object and the other
  application intact, removing the object is refused while an application still
  needs it, accepting the broken dependents removes it and the check report names
  the provider that is gone, and restoring the object makes the surviving
  application whole again.
  The WinGet importer reads a winget-pkgs manifest as YAML, takes its
  PackageIdentifier, PackageVersion, InstallerUrl and InstallerSha256, verifies an
  upper-case digest against the artifact beside the manifest, and carries it through
  the same writer the Scoop package uses. A PackageDependencies block becomes
  package requirements, every nested block that is not one is skipped and counted, and
  the installer, Windows and catalog keys are dropped with a count. Nothing runs the
  artifact, so the import returns decision-required.
  The Nix closure importer reads a capture that names its store paths, the output root,
  the entry points and the references between them, and emits one package per store
  path. Every store path has to sit beside the capture, since nothing builds a store,
  and each travels whole under /usr/lib/holy/private/NAME/store/STORE_PATH/. A
  reference to a carried store path becomes a package requirement, so one object two
  applications name has one owner and two dependents, and a reference to a store path
  the capture does not carry becomes a requirement whose original field is the store
  hash. One pass over a store path's own bytes confirms each reference the capture
  declares, and the report counts the ones the payload does not carry. Nix states no
  version, so every package records 0 and the store hash is its identity. A fixture
  installs the closure, removes one application and sees the object survive, and the
  removal of the object is refused while the other application still needs it. Nothing
  is executed, so the import returns decision-required and names the store view a Nix
  program with absolute paths would need.
  `holypkg split TREE --output NEW_FILE` now proposes the split outputs of a prepared
  tree before anyone writes them: every non-directory path receives one output, a path
  line records the reason, an explicit rule outranks the heuristic, and four cases stay
  decisions instead of assignments. A header, an include directory and pkg-config
  metadata are proposed for -devel, a versioned shared object and a license stay in the
  runtime output, and a man page or reference document is proposed for -doc. An
  unversioned object is a decision because the payload may dlopen it, a static archive
  is a decision because only the project knows, a link that leaves the tree or is
  absolute is a decision because a payload carries neither, and two rules naming
  different outputs for one path is a decision by definition. A fixture builds a real
  payload with a program, a versioned object, a plugin, an archive, headers, pkg-config,
  documentation and a license, and checks the proposal, the rules that settle it, the
  contradictions and the refusals.
  `holypkg split --debug` now adds a NAME-debug output whose files are cut from the
  runtime ELFs with objcopy, and the ELF reader reports the GNU build-id note so a
  stripped artifact and its debug file are matched by an identity instead of a name.
  Each debug record names the runtime path and that note, an ELF without a note is a
  decision because nothing would tie the pair together, and the proposal names the
  tool rather than inventing a per-file command. `elf FILE --build-id` reads the note
  section, so a separate debug file, which keeps the note and loses the loadable
  segments, is still checked. A fixture cuts a real pair with objcopy, keeps the note
  in both files, confirms the stripped file lost its debug sections and names its
  debug file, and drives GDB to the recorded source line and stack trace through the
  pair; the same artifact without its debug file resolves no line, which is what
  makes the debug output load-bearing.
  `make check-cc` now compiles the core with tcc, gcc and clang in turn, packs a
  package with each result and verifies it, and returns 6 when a toolchain is
  absent, so the three named host compilers are checked rather than assumed.
  The Solus eopkg importer reads a ZIP artifact holding metadata.xml, files.xml and
  an install tar, and emits one native package. The metadata is read as XML text in
  its own element context, so a Name under Source is a packager identity rather than
  the package name and a BuildDependencies entry is not a runtime requirement. Each
  RuntimeDependencies entry becomes one exact package requirement whose original
  field is the releaseFrom value, since a distribution release is a property of the
  repository and not of the dependency. Solus states no release, so the native one
  is 1, and an architecture this manager does not place is a decision rather than a
  guess. The install tar travels whole under /usr/lib/holy/private/NAME/eopkg/, a
  leading ./ is dropped, a member naming .. is refused, and a link that leaves the
  private tree becomes a recorded file requirement. An install script, a COMAR
  object, a delta, a signature and a declared file list are named in the report and
  dropped: nothing runs and no signature is trusted. A fixture converts a real
  artifact, installs the package beside a provider that closes the requirement,
  checks the private layout is what landed, and refuses a missing metadata, a
  missing install tar, a malformed document, an unplaceable path and an unknown
  architecture.
- [ ] Implement `holypkg run`, context-specific provider paths, grouped `up --prepare`,
  isolated root/VM trials and full `check` reports.
  The existing run launcher now derives private PATH directories from the
  selected installed manifest, so a public executable can invoke its own
  private helper by name. Explicit directory views bind package-owned private
  trees over existing /usr/lib or /app mountpoints in the child namespace.
  An explicit --auto-view now binds package-owned private regular files over
  existing matching public paths in the child namespace and refuses ambiguous
  mappings. The command after -- may now name a manifest-owned private file
  under /usr/lib/holy/private/ARTIFACT-ID/ with a bin directory and a plain file
  name after it, which is how a package whose payload is private starts its own
  entry point.
  `holypkg conflict` now reads the installed set and reports every capability two
  artifacts both offer: a package name two providers claim, a SONAME two providers
  claim, a file path two artifacts declare and a program name two private trees
  place in a bin directory, which the run PATH resolves by sort order. Two
  providers of one SONAME with different arch or libc records are an abi mismatch
  rather than a duplicate. A fixture installs a shared object and its consumer, adds
  a second provider of the same SONAME, a second artifact claiming one package name,
  two artifacts declaring one file path and two private programs of one name, and
  checks each finding, its reason and its provider list, alongside the refusals for a
  root with no database and a pending transaction. The claim collection behind that
  report is now shared with the set transaction: db plan-set states the capabilities
  its own selection offers twice, with the same kinds, reasons and provider list, and
  db apply-set prints the same findings before it stages the first payload file. A
  selection with two providers of one SONAME, two private programs of one name or
  two different-ABI offers of one name is reported in the plan rather than left to a
  later report. Conflicts between a selection and the already installed set remain
  outside the plan, and an automatic choice between two candidates remains open.

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
- [x] Select BusyBox, dinit, mdevd, glibc and musl from a pinned native source
  during image construction. Record each original hash and source ID, normalize
  the selected core packages, and preserve the source binding when the guest
  reinstalls libc from cache. The source-stage fixture and x86_64 two-boot
  ext4 QEMU contract pass. These inputs came from a disposable local catalog;
  a public Holy repository and i686 source-backed image remain open.
- [x] Convert the five existing user-owned bootstrap archives into a sealed,
  unsigned source-ready catalog with root-owned manifests in a user namespace.
  Keep the original and converted hashes, source ID, index digest and an
  includable image config. Fresh namespace resolvers accepted all five
  x86_64 and i686 packages for read-only install plans. The image source
  stage records each i686 placement decision and fetched all five i686 core
  artifacts. Publication, signatures and i686 boot testing remain open.
- [x] Accept a pinned native linux package as the image kernel input. Check
  its version, target architecture and extracted x86 boot header, install the
  original .holy with its source ID, and use its boot/vmlinuz for the ISO. An
  x86_64 ext4 image with five core packages from one source and linux from a
  second source passed the two-boot libc-removal/recovery QEMU contract.
  That first fixture kernel package contained the image without a module set.
- [x] Package a matching 7.2.7 x86_64 dummy.ko and modules.dep with a pinned
  native linux artifact. The ELF scanner accepts its ET_REL payload only at a
  kernel module path with matching .modinfo vermagic; a mismatched release
  fails the fixture. A full x86_64 ext4 image passed two QEMU/TCG boots. On
  each boot, the guest checked the module hash, loaded it with finit_module
  and found dummy in /proc/modules; the second boot followed removal and
  recovery of both dynamic libc packages. General module dependency handling,
  i686 kernel modules and hardware drivers remain open.
- [x] Add `make bootstrap-kernel` for an existing x86 kernel image and optional
  modules staging tree. It checks the boot header, modules.dep coverage,
  package manifest and ELF module facts, then records input and artifact
  hashes. Wrong architecture and missing modules.dep targets fail before
  publication. The generated linux.holy entered a pinned source catalog and
  passed the same x86_64 ext4 two-boot QEMU contract, including dummy load on
  both boots and libc removal/recovery. A kernel source recipe remains open.
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
  through frozen plan format 4 and retain that provenance at install. The live
  install fixture now carries its source config and artifact bindings into the
  target root, copies embedded pinned mirrors, and checks installed source
  records. A disposable-root fixture verifies source preservation and fetch
  after root relocation. A source-attributed full installed-disk VM run remains.
- [ ] Implement `holygetiso` with explicit inputs, installed man bundle and a
  boot-validated ISO for each target architecture. The first in-tree C99
  frontend now parses a single explicit local-input config, records its hash
  in the boot plan and drives the existing bootstrap/QEMU path. Additional
  relative includes now contribute to one frozen effective config; include
  cycles and duplicate scalar values fail before the build.
  Local .holy packages join its set plan and input record.
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
  tool paths and hashes, but does not archive their dependency closure. The
  explicit build-only path records untested and exits 6. The local-input and
  sealed-mirror builds above pass full QEMU gates. Explicit cross-source
  choices and unique native provider discovery now work for additional image
  packages. Relocatable installation remains open.

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
  and per-stage reports with boot numbers; repeated markers in one boot do not
  renew a deadline. The default removes copied boot inputs and writable
  overlays after reporting; QEMU_KEEP=1 retains them for inspection.
  A copied boot input is now measured on both sides of the copy: the source is
  hashed before and after, the copy is hashed, and the report records the three
  digests with copy_consistency. An unchanged source matching the copy is
  verified, a source that changed between the two readings is
  input-changed-during-copy, and a copy that differs from the unchanged source
  is copy-mismatch. Either state names the inputs in inconsistent_inputs and
  fails the run as inconsistent-input-copy. The measurement reports a race
  that happened and cannot rule out one that did not, so a live volume still
  needs a stopped image or a stable snapshot for a precise trial.
  `holypkg test PLAN` now verifies a saved update plan against a target root
  without changing it: it reports the plan, mode, source, catalog generation and
  the bound image, then eight checks over the plan inputs, each a fact about a
  bound record. A source id is the digest of its definition, so a registry
  record naming another id, definition or alias does not bind the plan; a
  catalog serving another index generation is not the generation the plan
  fixed; a new artifact that does not verify or does not fill the planned slot
  is not the prepared artifact. A root test binds its trial base as the
  installed generation with a digest of the installed artifact set, since a
  live rootfs has no stable whole-tree digest. The report counts pass, fail,
  skip and unknown with coverage plan-inputs, lists runtime probes as
  unexecuted until a test asks for them, and returns 4 for a failed check and
  6 for an unknown one. --json uses holy-test-report-1. A fixture covers the
  bound report, a VM mode that names the missing runner, and a deleted new
  archive, deleted old archive, drifted payload, removed slot, changed catalog
  generation, changed source id and lost alias. Running a command in a trial
  with --shell or -- COMMAND and the VM trial itself remain open, as does the
  Holy hardware gate. `-- COMMAND ARGS` now runs one command in a private root
  trial after a set that completed, and --shell runs $SHELL or /bin/sh. the trial
  makes private mount propagation, its own /proc, /run, /tmp and /home, PID, IPC
  and UTS namespaces, a user namespace where the host allows one and a controlled
  /dev with the standard character nodes and stream links, so no host socket,
  block device, home directory, D-Bus service or credential is passed on. the
  command runs as PID 1 of its own pid namespace with its argv unchanged and its
  status as the status, and a host that refuses the namespaces or the device nodes
  is 6 with the reason. the plan is verified against --root and is not applied, so
  a trial that applies a prepared plan still needs an isolated copy of the
  filesystem, which is open. check-root-trial carries the isolation properties and
  returns 6 on a host that refuses device nodes in a user namespace, as this one
  does, while check-plan-test proves the plan inputs.
- [ ] Boot both target architectures in QEMU and prove PID 1, shell, package
  install/removal and recovery after removing either or both dynamic libc runtimes.
- [ ] Run compiler/SDK, language, GUI, graphics, gaming, workstation and foreign
  source cases with pinned artifacts, logs, elapsed time and explicit coverage.
