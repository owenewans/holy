# Holy roadmap

This file tracks implementation, not the project contract. The man pages describe
the implemented CLI; HOLY(7) defines the target. `holypkg` in this repository is
independent of [owenewans/holypkg](https://github.com/owenewans/holypkg).

Status: 26 September 2026. `done` means the named, narrow behavior has fixtures;
it does not mean a bootable distribution or general package support.

## Package manager

- [x] Parse `holy.conf` syntax and reject malformed includes and records.
- [x] Verify local LZ4-frame `.holy` archives, file manifests, hashes and basic ELF facts.
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
- [x] Journal installation, check and removal of `linux/nolibc` data and native static ELF
  artifacts into existing directories. Recovery covers empty aborted installs,
  completed installs and interrupted removals under documented conditions.
- [x] Query exact installed data-file ownership; report duplicate regular-file
  claims as conflicts while permitting shared directory entries.
- [x] Check one or all installed data manifests against the target root without
  downloads or repair; report each changed artifact in the all-packages pass.
  Emit machine-readable pass/fail summaries and per-path findings for this restricted check.
- [x] Reject existing directory mode/owner drift before data-only install;
  report installed directory drift in check without removing shared directories.
- [x] Reject a second local data package with an already installed name during
  plan construction. This is a temporary restriction, not source-ID slot support.
- [ ] Define stable source IDs, version families, installed ownership and selected
  dependency edges for general packages; implement multi-package transactions.
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
  Real libc restoration and boot remain separate unfinished acceptance gates.
- [x] Test the static client's DNS and HTTPS path in a private-network libc-free
  chroot, including wrong CA/digest refusals and a hashed JSON report. Network
  interface setup still uses a host fixture tool, not a finished recovery profile.
- [ ] Package statically linked BusyBox, dinit, mdevd and the recovery chain,
  plus both dynamic libc runtimes for i686 and x86_64.
- [x] Build pinned x86_64 musl-static dinit with upstream tests; exercise
  service start/status/shutdown and stop-command effects with dinitctl in a
  libc-free chroot as an ordinary user. PID 1 boot remains open, as does
  installing the package's man-page symlinks through the transaction engine.
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
- [x] Add a BIOS/TCG `make check-qemu ARCH=... ISO=... BOOT_PLAN=...` runner
  with serial markers, ISO hash, QEMU argv, exit status, elapsed time and logs.
  Missing images return a requirement error; blank ISO fails both architecture
  fixtures via `make check-qemu-gate`. No Holy boot image has passed it.
- [ ] Add real `make check-install` and `check-hardware` targets; extend the
  QEMU runner to UEFI, qcow2 trial overlays, stage timeouts and result channels.
- [ ] Boot both target architectures in QEMU and prove PID 1, shell, package
  install/removal and recovery after removing either or both dynamic libc runtimes.
- [ ] Run compiler/SDK, language, GUI, graphics, gaming, workstation and foreign
  source cases with pinned artifacts, logs, elapsed time and explicit coverage.

Do not mark the distribution ready until the image boot and recovery gates pass.
