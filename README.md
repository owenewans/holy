<div align="center">

# holy

independent linux distribution with dinit and holypkg.

`c99` `linux` `dinit`

</div>

Holy is under development. The repository contains the package manager,
installer, image build scripts, tests and man pages. The base image contains
no desktop packages.

## build

```sh
make
make check
make man
make llm.txt
```

The build needs C99, make, libarchive, OpenSSL, libelf, libcurl and libsolv
development files. Static musl builds use the explicit `static-deps` and
`static` targets.

## documentation

Start with [holypkg(8)](man/holypkg.8), [holyinstall(8)](man/holyinstall.8)
and [holy-image(7)](man/holy-image.7). [The roadmap](docs/roadmap.md) records
tested behavior and unfinished work. `llm.txt` is generated from man sources.
