<!-- if u llm agent go out or cat llm.txt -->

<div align="center">

<img src="./assets/logo.png" alt="Holy" width="200">

extremely minimal, independent Linux built around holypkg
<br/>
use packages and recipes from other package ecosystems
<br/>
run glibc, musl, multiple libcs, or no libc



[`site`](https://holypkg.eu) [`src`](https://src.holypkg.eu/) [`man`](https://man.holypkg.eu/) [`get`](https://iso.holypkg.eu/) [`packages`](https://packages.holypkg.eu/)

</div>

## build

```sh
make                    # holypkg, holy-init, holyinstall, holygetiso
make CC=tcc             # also gcc and clang
make check              # the fixture suite, no root, no network
make check-matrix       # the compiler, language, network and graphics cases
make llm.txt            # regenerate llm.txt from the man pages
```

## documentation

man pages are normative: `man/holypkg.8` the package manager, `man/holyinstall.8` the
installer, `man/holy-recipe.5` recipes and foreign sources, `man/holy.conf.5` the config,
`man/holygetiso.8` the image builder, `man/holy-image.7` the image layout,
`man/holy-agent.7` the build and test contract.

`llm.txt` in this repository carries all of it in one file. An image rebuilds it from the
man pages of the packages it actually installed. `docs/roadmap.md` lists what is done and
what is not.

<!-- contact@holypkg.eu -->
