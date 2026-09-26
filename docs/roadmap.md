# Holy roadmap

This file tracks implementation, not the project contract. The man pages describe
the implemented CLI; HOLY(7) defines the target. `holypkg` in this repository is
independent of [owenewans/holypkg](https://github.com/owenewans/holypkg).

Status: 26 September 2026. `done` means the named, narrow behavior has fixtures;
it does not mean a bootable distribution or general package support.

## Package manager

- [x] Parse `holy.conf` syntax and reject malformed includes and records.
- [x] Verify local LZ4-frame `.holy` archives, file manifests, hashes and basic ELF facts.
- [x] Stage verified objects in a target-root cache; preview collisions.
- [x] Build and seal a local repository catalog; search and fetch its verified objects.
- [x] Resolve a restricted local/catalog graph with libsolv; reject unsupported semantics.
- [x] Journal installation, check and removal of **data-only** `linux/noarch/nolibc`
  artifacts into existing directories. Recovery covers empty aborted installs,
  completed installs and interrupted removals under documented conditions.
- [x] Query exact installed data-file ownership; report duplicate regular-file
  claims as conflicts while permitting shared directory entries.
- [x] Reject a second local data package with an already installed name during
  plan construction. This is a temporary restriction, not source-ID slot support.
- [ ] Define stable source IDs, version families, installed ownership and selected
  dependency edges for general packages; implement multi-package transactions.
- [ ] Install executable and shared-library payloads with ABI-aware linking,
  private providers, interpreter handling and explicit conflict decisions.
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

- [ ] Package statically linked BusyBox, dinit, mdevd and the recovery chain,
  plus both dynamic libc runtimes for i686 and x86_64.
- [ ] Package Limine, dracut, kernel, firmware, SDK/sysroots and the default
  ConnMan+iwd network profile; test static local and HTTPS libc recovery.
- [ ] Implement C99 `holyinstall` with reviewed disk/boot/account/network plans
  and `holypkg --root` integration.
- [ ] Implement `holygetiso` with explicit inputs, installed man bundle and a
  boot-validated ISO for each target architecture.

## Acceptance gates

- [x] Run current prototype fixtures under GCC, TCC and Clang ASan/UBSan.
- [ ] Add real `make check-root`, `check-qemu`, `check-install` and
  `check-hardware` targets; unavailable inputs must fail or report skip.
- [ ] Boot both target architectures in QEMU and prove PID 1, shell, package
  install/removal and recovery after removing either or both dynamic libc runtimes.
- [ ] Run compiler/SDK, language, GUI, graphics, gaming, workstation and foreign
  source cases with pinned artifacts, logs, elapsed time and explicit coverage.

Do not mark the distribution ready until the image boot and recovery gates pass.
