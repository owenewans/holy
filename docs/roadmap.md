# Holy roadmap


## Package manager

- [x] Parse `holy.conf` syntax and reject malformed includes and records.
- [x] Verify local LZ4-frame `.holy` archives, file manifests, hashes and basic ELF facts.
- [x] Read dynamic symbols, binding/visibility and per-symbol GNU versions through
  libelf, including ELF32/ELF64 without section headers when the hash tables give
  a symbol count. Preserve weak imports and compatibility/default versions.
  Symbol lookup order and dependency-provider validation remain open.
- [x] Classify static ET_EXEC without dynamic linkage as nolibc; reject
  unclassified ELF in native package scan rather than trusting a libc label.
- [x] Pack a prepared regular-file/dir/symlink tree into a verified native `.holy`;
  reject unlisted inputs and unsupported file types before publication.
- [x] Generate a prepared DATA tree's regular-file/dir/symlink HOLY/files manifest
  with numeric ownership and SHA-256; reject unsupported objects.
- [x] Stage verified objects in a target-root cache; preview collisions.
- [x] Fetch a pinned native `.holy` over HTTPS with certificate checks and a
  local CA fixture; reject credential-bearing redirect targets before making
  redirected requests. Configured source sync and signatures remain open.
- [x] Build and seal a local repository catalog; search and fetch its verified objects.
- [x] Resolve a restricted local/catalog graph with libsolv; reject unsupported semantics.
- [x] Add observed ELF interpreter, SONAME and strong symbol edges to that graph;
  reject candidate class/ABI/version/symbol mismatches and expose stable IDs for
  root provider choices. Unresolved launch scopes report unknown. File placement,
  complete loader contexts and integration with dynamic-package transactions remain open.
- [x] Export canonical selected artifact/edge records from the resolver; bind the
  supported install subset to its graph in the plan hash and installed state.
  Graph integrity checks preserve legacy state compatibility.
- [x] Journal installation, check and removal of `linux/nolibc` data and native static ELF
  artifacts into existing directories. Recovery covers empty aborted installs,
  completed installs and interrupted removals under documented conditions.
- [x] Install relative symlinks with recorded targets and ownership; check, remove
  and recover them without following the links. Absolute links and hardlinks
  remain outside the transaction subset.
- [x] Query exact installed data-file ownership; report duplicate regular-file
  claims as conflicts while permitting shared directory entries.
- [x] Check one or all installed data manifests against the target root without
  downloads or repair; report each changed artifact in the all-packages pass.
  Emit machine-readable pass/fail summaries and per-path findings for this restricted check.
- [x] Reject existing directory mode/owner drift before data-only install;
  report installed directory drift in check without removing shared directories.
- [x] Reject a second local data package with an already installed name during
  plan construction. This is a temporary restriction, not source-ID slot support.
- [x] Install a resolved cached static/data set with one writer lock, plan hash
  and generation change; persist reasons/edges, reject referenced-provider removal,
  and recover completed sets or resume untouched remaining packages after failure.
  The bootstrap image installs its base through this set engine.
- [ ] Define stable source IDs and version families; extend transactions to
  installed-provider reuse, replacements, dynamic libraries and grouped removal.
- [ ] Install executable and shared-library payloads with ABI-aware linking,
  private providers, interpreter handling and explicit conflict decisions.
- [x] Install, run, check and remove a native static syscall-only ELF fixture;
  foreign-architecture approval and dynamic payload installation remain open.
- [ ] Handle hooks, service consent, modified configs, overrides, rollback and
  recovery of each interrupted mutation phase.
- [ ] Implement native HTTPS/Git source synchronization, signed generations and
  cache retention with provenance.
- [ ] Implement foreign binary adapters and file indexes with real fixtures:
  pacman, APT/DEB, RPM, APK, XBPS, Slackware and eopkg.
- [ ] Implement AUR, Aports, xbps-src, SlackBuilds, RPM spec, Debian source,
  Gentoo and Pacstall recipe conversion with helper environments and split outputs.
- [ ] Implement Nix closure, Flatpak, Snap, AppImage, Scoop and WinGet imports
  without silently discarding runtime requirements.
- [ ] Implement `holypkg run`, context-specific provider paths, `up --prepare`,
  isolated root/VM trials and full `check` reports.

## Base system and images

- [x] Build pinned x86_64 musl-static BusyBox as a native package and test its
  installed shell in a chroot without dynamic libc directories. Build logs,
  source/config/artifact hashes and upstream license files are retained.
  This bootstrap profile does not supply static holypkg or network recovery.
- [x] Link the prototype holypkg with musl-static dependencies; verify native
  archive, ELF, repository, solver and HTTPS fixtures. Run local package
  cache/install/check/remove and BusyBox shell probes inside a libc-free chroot.
  Real libc restoration remains an unfinished acceptance gate.
- [x] Test the static client's DNS and HTTPS path in a private-network libc-free
  chroot, including wrong CA/digest refusals and a hashed JSON report. Network
  interface setup still uses a host fixture tool, not a finished recovery profile.
- [ ] Package statically linked BusyBox, dinit, mdevd and the recovery chain,
  plus both dynamic libc runtimes for i686 and x86_64.
- [x] Build pinned x86_64 musl-static dinit with upstream tests; exercise
  service start/status/shutdown and stop-command effects with dinitctl in a
  libc-free chroot as an ordinary user. Install/check/remove the complete package,
  including command and man-page symlinks, through the transaction engine.
  The static-core image also exercises dinit as PID 1.
- [x] Build pinned x86_64 musl-static mdevd/skalibs with licenses and upstream
  HTML docs. Install, check and remove the package; parse valid symbolic-owner
  configuration and reject invalid regex inside a libc-free chroot with a
  private network namespace. The static-core image exercises readiness, coldplug
  and dinit integration; client libudev compatibility remains separate.
- [x] Build an x86_64 static-core ISO through native package transactions, a
  private dracut sysroot and Limine. Audit initramfs payloads against the installed
  root and reject dynamic ELF. Boot with dinit as PID 1, BusyBox, mdevd/coldplug
  and a local package install/check/remove in QEMU. This RAM profile does not
  yet install an on-disk system or restore dynamic libc.
- [ ] Package Limine, dracut, kernel, firmware, SDK/sysroots and the default
  ConnMan+iwd network profile; test static local and HTTPS libc recovery.
- [ ] Implement C99 `holyinstall` with reviewed disk/boot/account/network plans
  and `holypkg --root` integration.
- [ ] Implement `holygetiso` with explicit inputs, installed man bundle and a
  boot-validated ISO for each target architecture.

## Acceptance gates

- [x] Run current prototype fixtures under GCC, TCC and Clang ASan/UBSan.
- [x] Run `make check-root` against disposable target-root install, check,
  remove and recovery fixtures; this gate does not boot a system.
- [x] Add a BIOS/UEFI `make check-qemu ARCH=... ISO=... BOOT_PLAN=...` runner
  with serial markers, ISO hash, QEMU argv, exit status, elapsed time and logs.
  Missing images return a requirement error; blank ISO fails both architecture
  fixtures via `make check-qemu-gate`. Cancellation reaps the guest and records
  failure. The x86_64 static-core ISO passes BIOS/TCG and UEFI/TCG boot contracts.
- [ ] Add real `make check-install` and `check-hardware` targets; extend the
  QEMU runner to qcow2 trial overlays and per-probe timeouts/result channels.
- [ ] Boot both target architectures in QEMU and prove PID 1, shell, package
  install/removal and recovery after removing either or both dynamic libc runtimes.
- [ ] Run compiler/SDK, language, GUI, graphics, gaming, workstation and foreign
  source cases with pinned artifacts, logs, elapsed time and explicit coverage.
