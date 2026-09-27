# Holy roadmap

## Current state

- [x] Boot the x86_64 live ISO, prepare a blank GPT guest disk in holyinstall,
  install the target root, then boot the installed disk through BIOS and UEFI
  under QEMU/TCG. The installed guest checks dinit, holypkg, package repair
  and local password login; a wrong password is rejected. The two VM reports
  use the same fixture image and do not establish i686 installer support.
- [x] Install a static OpenDoas package through a separate artifact-approved
  set transaction on the guest disk. BIOS and UEFI boots authenticate the
  local account and then run the scoped BusyBox UID command through doas;
  the PTY probe supplies its password and checks UID 0. The fixture uses a
  local shadow account and does not cover PAM/NSS or an account menu.


## Package manager

- [x] Bind explicit non-native architecture placement decisions to individual
  selected artifact hashes, the plan and the recovery journal. Preserve host and
  target in installed state and check output, retain decisions for reused
  providers, and reject inheritance by new update artifacts. Automatic runtime
  capability detection and update-specific architecture decisions remain open.

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
  transaction fixtures. Other comparators remain open.

- [x] Resolve declared package aliases using their own versions and artifact ABI
  scopes. Preserve claims and their hash in holy-instance-4, discover installed
  aliases, and reject updates dropping required capabilities. Read legacy state
  through verified cached artifacts when alias metadata is needed. File, command
  and build claims still need dependency resolution support.

- [x] Build gzip, LZ4, Zstandard, XZ and bzip2 codecs into the static musl client.
  Verify foreign import and native install/check/remove in a chroot without
  dynamic libc or external decoders; reject truncated compressed inputs.

- [x] Import local pacman binary archives through libarchive into verified native
  outputs, preserve original artifacts and metadata, classify/split known ELF ABIs,
  and bind outputs with a conversion receipt. Fixtures cover an actual gzip
  PKGINFO, links, malformed archives, inactive hooks and data installation.
  Repository sync, publisher verification, config files, recipe import and full
  foreign relation/hook/transform installation remain open.

- [x] Parse `holy.conf` syntax and reject malformed includes and records.
- [x] Plan and atomically apply a source identity registry under the database
  writer lock. Preserve IDs across alias changes and retain inactive origin
  history; reject stale, wrong-root and history-dropping plans. Apply consumes
  the reviewed plan without rereading user includes. Configured sync, automatic source-aware update selection and trust enforcement remain open.
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
  redirected requests. Configured source sync and signatures remain open.
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
- [x] Reject existing directory mode/owner drift before data-only install;
  report installed directory drift in check without removing shared directories.
- [x] Compare installed slots by source-id, name, os, arch and libc. Permit distinct
  slots with compatible ownership and reject a second active version of one slot.
  Same-name glibc/musl executables run in the dual-libc chroot fixture. Multiple
  installed instances of the same artifact remain open.
- [x] Install a resolved cached static/data set with one writer lock, plan hash
  and generation change; persist reasons/edges, reject referenced-provider removal,
  and recover completed sets or resume untouched remaining packages after failure.
  The bootstrap image installs its base through this set engine.
- [x] Install glibc/musl dynamic sets with explicit interpreter and DT_NEEDED
  payload paths; execute real fixtures in a disposable x86_64 root. Report broken
  selected provider files through installed check. Ordinary SONAME search and
  automatic path conversion still require implementation.
- [x] Plan and journal missing-only repair from the verified artifact cache.
  Preserve changed/partial files, reject stale plans and resume recorded repair
  after injected write failure. General reinstall and config merge remain open.
- [x] Discover installed providers through package names and literal ELF paths;
  scan cached archives of the resulting candidate closure. Reuse intact version-2/3
  instances without changing their state, reason, graph or payload. Bind reused
  state into plans and validate it during interrupted-set recovery. Named loader
  search, automatic preference ranking and cache-independent discovery remain open.
- [x] Report orphan dependency instances by traversing saved edges from explicit
  roots. Ignore stale edges belonging to removed consumers; detect unreachable
  cycles and preserve shared providers. The read-only command works without cache
  artifacts and refuses incomplete, missing-provider or unknown-graph snapshots.
- [ ] Complete source-aware installed slots and version families; extend transactions to
  replacements, complete dynamic-library contexts and grouped removal. The
  explicit --accept-broken removal path now retains consumers and reports their
  broken edges; durable completed-transaction decisions remain unfinished.
- [ ] Install executable and shared-library payloads with ABI-aware linking,
  private providers, interpreter handling and explicit conflict decisions.
- [x] Install, run, check and remove a native static syscall-only ELF fixture;
  foreign-architecture approval remains open.
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
  source identity across alias changes. Fetching candidates, new dependency
  selection and grouped replacements remain open.
- [x] Apply the reviewed cached replacement with one writer lock and generation
  change. Stage changed payload, journal individual transitions, publish the next
  installed database and retain the old records. Rewrite consumer edges while
  preserving reasons/source identity. Recover interrupted publication after
  injected SIGKILL and ENOSPC; preserve partial staging for explicit inspection.
  Test file addition/removal, regular/symlink transitions and a compatible ELF
  provider update. Hooks, config merging and general rollback remain open.
- [x] Create missing manifest directories before payload installation, update or
  repair. Validate every absent parent, preserve existing modes/owners and publish
  prepared directories without replacement. Handle arbitrary archive entry order;
  recover exact staged/published directories in interrupted sets and updates.
  Reject symlinked parents, changed metadata and partially initialized staging.
  Retain directories and untracked contents on removal. Full directory metadata
  changes, privileged ownership and general single-install resume remain open.
- [ ] Implement native HTTPS/Git source synchronization, signed generations and
  cache retention with provenance.
- [x] Mirror an explicitly pinned HTTPS native catalog into a new sealed local
  snapshot through the common transport. Verify all artifact hashes, identity,
  payload and claims before publishing current; retain unsigned URL/digest
  provenance. Fixture TLS covers search/solve/fetch, escaped filenames, empty,
  duplicate/truncated indexes, false claims, bad hashes, missing URLs and limits.
  Configured source activation and publisher signatures remain open.
- [ ] Implement foreign binary adapters and file indexes with real fixtures:
  pacman, APT/DEB, RPM, APK, XBPS, Slackware and eopkg.
- [ ] Implement AUR, Aports, xbps-src, SlackBuilds, RPM spec, Debian source,
  Gentoo and Pacstall recipe conversion with helper environments and split outputs.
- [ ] Implement Nix closure, Flatpak, Snap, AppImage, Scoop and WinGet imports
  without silently discarding runtime requirements.
- [ ] Implement `holypkg run`, context-specific provider paths, `up --prepare`,
  isolated root/VM trials and full `check` reports.

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
- [ ] Implement `holygetiso` with explicit inputs, installed man bundle and a
  boot-validated ISO for each target architecture.

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
- [ ] Add a real `check-hardware` target; extend the QEMU runner to qcow2 trial
  overlays and per-probe timeouts/result channels.
- [ ] Boot both target architectures in QEMU and prove PID 1, shell, package
  install/removal and recovery after removing either or both dynamic libc runtimes.
- [ ] Run compiler/SDK, language, GUI, graphics, gaming, workstation and foreign
  source cases with pinned artifacts, logs, elapsed time and explicit coverage.
