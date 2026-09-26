<div align="center">

# holy

independent linux distribution in development.

<a href="https://count.owenewans.org/owenewans/holy?theme=moebooru-h&amp;notitle"><img src="https://count.owenewans.org/owenewans/holy?theme=moebooru-h&amp;notitle" alt="repository views"></a>

`c` `linux` `distribution`

</div>

## build

Requires libarchive, libelf and OpenSSL:

```sh
make
make check
```

`make install` installs the current `holypkg` prototype, man pages and generated
`llm.txt`. Fixtures also need tar, lz4, sha256sum, GCC, setfattr, setfacl,
objcopy, as and ld.

## status

The C99 prototype verifies local `.holy` archives, inspects ELF and typed
requirements, checks files and previews root path conflicts without installing.
It can build, seal, search and fetch an unsigned local repository catalog.
Installed-state transactions, a bootable image and QEMU acceptance are pending.
The [Slackware holypkg](https://github.com/owenewans/holypkg) is a separate project.

## documentation

Read [holypkg(8)](man/holypkg.8), [holy-package(5)](man/holy-package.5) and
[holy.conf(5)](man/holy.conf.5) for the implemented interface.
