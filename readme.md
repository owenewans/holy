<div align="center">

# holy

independent linux distribution in development.

<a href="https://count.owenewans.org/owenewans/holy?theme=moebooru-h&amp;notitle"><img src="https://count.owenewans.org/owenewans/holy?theme=moebooru-h&amp;notitle" alt="repository views"></a>

`c` `linux` `distribution`

</div>

## build

Requires libarchive, libelf, libcurl, OpenSSL and libsolv development files:

```sh
make
make check
make check-root
```

`make install` installs the current `holypkg` prototype, man pages and generated
`llm.txt`. Fixtures also need tar, lz4, sha256sum, GCC, setfattr, setfacl,
objcopy, as and ld.
`make check` includes the internal libsolv fixture. libsolv development files
must be available through pkg-config; the check fails if they are absent.
`make check-root` exercises package mutations only inside disposable target
directories. It does not test a booted system.
`make check-qemu-gate` runs negative BIOS/TCG fixtures.
`make check-qemu ARCH=x86_64 ISO=FILE BOOT_PLAN=SHA256` requires a Holy ISO and guest
serial probes; the repository does not yet produce one.

## status

The C99 prototype verifies local `.holy` archives, inspects ELF, typed
requirements and capability claims, and checks root path conflicts.
`holypkg pack` writes a verified `.holy` from a prepared tree of ordinary
files and directories; recipes and foreign conversion remain open.
It stages verified archives in a target-root cache.
It can download a pinned native `.holy` over verified HTTPS to a local directory.
It can initialize an empty target-root package database and reserve or cancel
one verified cached artifact at a fixed generation. `db preflight` checks that
reservation against the target root. `db plan`, `db approve` and `db apply`
install a restricted, data-only package into existing directories with a
journal. `db check` compares installed data with rootfs; `db rm` removes an
intact instance. Restricted recovery handles untouched installs, completed
installs with a stale journal, and interrupted removals.
It can build, seal, search exact provider claims and fetch an unsigned local
repository catalog. The catalog records package capability claims; candidate
lookup validates matching artifacts against those claims.
`holypkg solve` and `repo solve` check narrow, read-only package graphs; source
resolution and version-family comparators are pending.
General installed-state transactions, a bootable image and QEMU acceptance are pending.
The [Slackware holypkg](https://github.com/owenewans/holypkg) is a separate project.

## documentation

Read [holypkg(8)](man/holypkg.8), [holy-package(5)](man/holy-package.5) and
[holy.conf(5)](man/holy.conf.5) for the implemented interface.
See [roadmap](docs/roadmap.md) for remaining work and acceptance gates.
