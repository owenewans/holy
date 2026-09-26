# Holy

<div align="center"><img src="https://count.owenewans.org/owenewans/holy?theme=moebooru-h&amp;notitle" alt="Holy views"></div>

Holy is a planned independent Linux distribution. This repository starts with
the C99 configuration parser and read-only local package inspector/verifier.
The verifier handles regular files, symlinks, directories and direct hardlinks.
Local fetch copies objects by SHA-256 without installing them.
Local extract handles regular files, directories and safe links in a new output directory.
Local check compares a package payload against a chosen root without changing it.
Local scan reads ELF payload facts and rejects known arch/libc tag mismatches.
Holy does not contain a bootable distribution yet.

Run `make` to build `holypkg` and `make check` to test it. `make install`
installs the binary, man pages and generated `llm.txt`. Read
`man/holy.conf.5`, `man/holy-package.5` and `man/holypkg.8` for the implemented
interface. Builds require libarchive, libelf and OpenSSL; fixtures also require tar,
lz4, sha256sum, setfattr, setfacl, objcopy, as and ld. Package installation, ISO images and runtime acceptance
tests remain unimplemented.

The similarly named `owenewans/holypkg` repository is a separate project.
