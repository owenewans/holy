<div align="center">

# holy

independent linux distribution in development.

<a href="https://count.owenewans.org/owenewans/holy?theme=moebooru-h&amp;notitle"><img src="https://count.owenewans.org/owenewans/holy?theme=moebooru-h&amp;notitle" alt="repository views"></a>

`c` `linux` `distribution`

</div>

## build

Requires libarchive, libelf, OpenSSL and libsolv development files:

```sh
make
make check
```

`make install` installs the current `holypkg` prototype, man pages and generated
`llm.txt`. Fixtures also need tar, lz4, sha256sum, GCC, setfattr, setfacl,
objcopy, as and ld.
`make check` includes the internal libsolv fixture. libsolv development files
must be available through pkg-config; the check fails if they are absent.

## status

The C99 prototype verifies local `.holy` archives, inspects ELF, typed
requirements and capability claims, and checks root path conflicts.
It stages verified archives in a target-root cache.
It can initialize an empty target-root package database and reserve or cancel
one verified cached artifact at a fixed generation. `db preflight` checks that
reservation against the target root. `db plan`, `db approve` and `db apply`
install a restricted, data-only package into existing directories with a
journal. Incomplete transactions require manual inspection.
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
