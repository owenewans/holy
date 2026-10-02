CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2
LDFLAGS ?=
LDLIBS ?= -larchive -lcrypto -lelf -lcurl -lplist-2.0 -lz
RPM_CFLAGS ?= $(shell pkg-config --cflags rpm 2>/dev/null)
RPM_LIBS ?= $(shell pkg-config --libs rpm 2>/dev/null)
RPMMD_CFLAGS ?= $(shell pkg-config --cflags libxml-2.0 2>/dev/null)
RPMMD_LIBS ?= $(if $(RPM_LIBS),$(shell pkg-config --libs libxml-2.0 2>/dev/null))
CPPFLAGS += $(if $(RPM_LIBS),-DHOLY_HAVE_RPM $(RPM_CFLAGS))
CPPFLAGS += $(if $(RPMMD_LIBS),-DHOLY_HAVE_RPMMD $(RPMMD_CFLAGS))
LDLIBS += $(RPM_LIBS) $(RPMMD_LIBS)
PREFIX ?= /usr
DESTDIR ?=
MANPAGES = $(wildcard man/*.[578])
SOLV_CFLAGS ?= $(patsubst -I%,-isystem %,$(shell pkg-config --cflags-only-I libsolv 2>/dev/null)) $(shell pkg-config --cflags-only-other libsolv 2>/dev/null)
SOLV_LIBS ?= $(shell pkg-config --libs libsolv 2>/dev/null) -lz

.PHONY: force-build-config
.build-config: force-build-config
	$(eval holy_build_config_tmp := $(shell mktemp "$@.tmp.XXXXXX"))
	$(file >$(holy_build_config_tmp),CC=$(CC))
	$(file >>$(holy_build_config_tmp),CPPFLAGS=$(CPPFLAGS))
	$(file >>$(holy_build_config_tmp),CFLAGS=$(CFLAGS))
	$(file >>$(holy_build_config_tmp),LDFLAGS=$(LDFLAGS))
	$(file >>$(holy_build_config_tmp),LDLIBS=$(LDLIBS))
	$(file >>$(holy_build_config_tmp),RPMMD_LIBS=$(RPMMD_LIBS))
	$(file >>$(holy_build_config_tmp),SOLV_CFLAGS=$(SOLV_CFLAGS))
	$(file >>$(holy_build_config_tmp),SOLV_LIBS=$(SOLV_LIBS))
	@cmp -s "$(holy_build_config_tmp)" "$@" || mv "$(holy_build_config_tmp)" "$@"
	@rm -f "$(holy_build_config_tmp)"

.DEFAULT_GOAL := all

.PHONY: fetch-sources fetch-bootstrap-sources
fetch-sources:
	@test -n "$(INPUTS)" || { echo 'INPUTS directory required' >&2; exit 2; }
	sh tools/fetch-sources.sh "$(INPUTS)" profiles/static-sources $(SOURCES)

fetch-bootstrap-sources:
	@test -n "$(INPUTS)" || { echo 'INPUTS directory required' >&2; exit 2; }
	sh tools/fetch-sources.sh "$(INPUTS)" profiles/bootstrap-sources $(SOURCES)

.PHONY: all check check-fixtures check-root check-qemu check-qemu-gate check-hardware check-https check-solver check-install-payload check-install bootstrap-busybox check-bootstrap-busybox check-static-core man
all: holypkg holy-init holyinstall holygetiso

holygetiso: src/getiso.o src/config.o src/sign.o
	$(CC) $(LDFLAGS) -o $@ $^ -lcrypto

holyinstall: src/installer.o src/disk.o src/config.o
	$(CC) $(LDFLAGS) -o $@ $^ -lcrypto

holy-init: src/early-init.c .build-config
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic $(LDFLAGS) -o $@ $<

.PHONY: bootstrap-musl check-musl-abi check-libc-abi
bootstrap-musl: holypkg
	ARCH="$(or $(ARCH),x86_64)" sh tools/bootstrap-musl.sh ./holypkg "$(INPUTS)" "$(or $(OUTPUT),out/musl-bootstrap)"

check-musl-abi:
	python3 tests/libc-abi.py "$(STATIC_HOLYPKG)" "$(MUSL32_PACKAGE)" "$(MUSL32_CC)" "$(MUSL_PACKAGE)" "$(MUSL_CC)"

check-libc-abi:
	python3 tests/libc-abi.py "$(STATIC_HOLYPKG)" "$(MUSL32_PACKAGE)" "$(MUSL32_CC)" "$(MUSL_PACKAGE)" "$(MUSL_CC)" "$(GLIBC32_PACKAGE)" "$(GLIBC_PACKAGE)"

.PHONY: bootstrap-glibc check-bootstrap-glibc
bootstrap-glibc: holypkg
	ARCH="$(or $(ARCH),x86_64)" sh tools/bootstrap-glibc.sh ./holypkg "$(INPUTS)" "$(or $(OUTPUT),out/glibc-bootstrap)"

check-bootstrap-glibc:
	@test "$$(id -u)" != 0 && test -f "$(or $(OUTPUT),out/glibc-bootstrap)/glibc.holy" || { echo 'ordinary user and completed glibc build required' >&2; exit 6; }
	$(MAKE) -C "$(or $(OUTPUT),out/glibc-bootstrap)/build" -j"$(or $(JOBS),2)" check

.PHONY: bootstrap-image
bootstrap-image: holypkg llm.txt
	ARCH="$(or $(ARCH),x86_64)" ROOT_STORAGE="$(or $(ROOT_STORAGE),ram)" IMAGE_PROFILE="$(or $(IMAGE_PROFILE),dual-libc)" LIBC_BOOT_STATE="$(or $(LIBC_BOOT_STATE),present)" INSTALL_TEST="$(or $(INSTALL_TEST),0)" INSTALL_FIRMWARE="$(or $(INSTALL_FIRMWARE),$(if $(filter i686,$(ARCH)),bios,both))" STORAGE_TOOLS_PACKAGE="$(STORAGE_TOOLS_PACKAGE)" DOAS_PACKAGE="$(DOAS_PACKAGE)" UEFI_CODE="$(UEFI_CODE)" UEFI_VARS="$(UEFI_VARS)" NETWORK_RECOVERY="$(or $(NETWORK_RECOVERY),off)" GLIBC_PACKAGE="$(GLIBC_PACKAGE)" MUSL_PACKAGE="$(MUSL_PACKAGE)" GLIBC_CC="$(or $(GLIBC_CC),gcc)" MUSL_CC="$(MUSL_CC)" STATIC_HOLYINSTALL="$(STATIC_HOLYINSTALL)" sh tools/bootstrap-image.sh ./holypkg "$(STATIC_HOLYPKG)" "$(STATIC_CC)" "$(BUSYBOX_PACKAGE)" "$(DINIT_PACKAGE)" "$(MDEVD_PACKAGE)" "$(KERNEL_IMAGE)" "$(KERNEL_VERSION)" "$(LIMINE_DIR)" "$(OUTPUT)"

.PHONY: bootstrap-kernel
bootstrap-kernel: holypkg
	@test -n "$(KERNEL_IMAGE)" && test -n "$(KERNEL_VERSION)" && test -n "$(OUTPUT)" || { echo 'bootstrap-kernel requires KERNEL_IMAGE, KERNEL_VERSION and OUTPUT' >&2; exit 2; }
	sh tools/bootstrap-kernel.sh ./holypkg "$(KERNEL_IMAGE)" "$(KERNEL_VERSION)" "$(or $(ARCH),x86_64)" "$(or $(MODULES_DIR),-)" "$(OUTPUT)"

.PHONY: source-ready-core
source-ready-core: holypkg
	@test -n "$(OUTPUT)" && test -n "$(SOURCE_ALIAS)" && test -n "$(SOURCE_URL)" && \
		test -n "$(BUSYBOX_PACKAGE)" && test -n "$(DINIT_PACKAGE)" && \
		test -n "$(MDEVD_PACKAGE)" && test -n "$(GLIBC_PACKAGE)" && \
		test -n "$(MUSL_PACKAGE)" || { echo 'source-ready-core requires output, source and five package inputs' >&2; exit 2; }
	sh tools/source-ready-core.sh ./holypkg "$(OUTPUT)" "$(SOURCE_ALIAS)" "$(SOURCE_URL)" \
		"$(BUSYBOX_PACKAGE)" "$(DINIT_PACKAGE)" "$(MDEVD_PACKAGE)" \
		"$(GLIBC_PACKAGE)" "$(MUSL_PACKAGE)"

.PHONY: check-image-source
check-image-source: holypkg holyinstall holygetiso
	sh tests/image-source.sh ./holypkg

.PHONY: check-run
check-run: holypkg
	sh tests/run.sh ./holypkg

.PHONY: check-repo-sign
check-repo-sign: holypkg
	sh tests/repo-sign.sh ./holypkg

.PHONY: check-repo-closure
check-repo-closure: holypkg
	sh tests/repo-closure.sh ./holypkg

.PHONY: check-git-source
check-git-source: holypkg holygetiso
	sh tests/git-source.sh ./holypkg
	sh tests/install-source-stage.sh ./holypkg

.PHONY: bootstrap-storage
bootstrap-storage: holypkg
	ARCH="$(or $(ARCH),x86_64)" sh tools/bootstrap-storage.sh ./holypkg "$(UTIL_LINUX_SOURCE)" "$(DOSFSTOOLS_SOURCE)" "$(E2FSPROGS_SOURCE)" "$(LIMINE_BINARY)" "$(STATIC_PREFIX)" "$(or $(OUTPUT),out/storage-bootstrap)"

.PHONY: check-bootstrap-storage
check-bootstrap-storage: holypkg
	sh tests/bootstrap-storage.sh ./holypkg "$(or $(STORAGE_TOOLS_PACKAGE),out/storage-bootstrap/holy-storage-tools.holy)"

.PHONY: bootstrap-doas
bootstrap-doas: holypkg
	ARCH="$(or $(ARCH),x86_64)" sh tools/bootstrap-doas.sh ./holypkg "$(DOAS_SOURCE)" "$(STATIC_PREFIX)" "$(or $(OUTPUT),out/doas-bootstrap)"

.PHONY: check-bootstrap-doas
check-bootstrap-doas: holypkg
	sh tests/bootstrap-doas.sh ./holypkg "$(or $(DOAS_PACKAGE),out/doas-bootstrap/doas.holy)"

.PHONY: bootstrap-dinit check-bootstrap-dinit
.PHONY: bootstrap-mdevd check-bootstrap-mdevd
bootstrap-mdevd: holypkg
	ARCH="$(or $(ARCH),x86_64)" STATIC_PREFIX="$(STATIC_PREFIX)" sh tools/bootstrap-mdevd.sh ./holypkg "$(INPUTS)" "$(or $(OUTPUT),out/mdevd-bootstrap)"

check-bootstrap-mdevd: holypkg
	sh tests/bootstrap-mdevd.sh ./holypkg "$(or $(MDEVD_PACKAGE),out/mdevd-bootstrap/mdevd.holy)"

bootstrap-dinit: holypkg
	ARCH="$(or $(ARCH),x86_64)" sh tools/bootstrap-dinit.sh ./holypkg "$(INPUTS)" "$(or $(OUTPUT),out/dinit-bootstrap)"

check-bootstrap-dinit: holypkg
	sh tests/bootstrap-dinit.sh ./holypkg "$(or $(DINIT_PACKAGE),out/dinit-bootstrap/dinit.holy)" "$(or $(BUSYBOX_PACKAGE),out/busybox-bootstrap/busybox.holy)"

bootstrap-busybox: holypkg
	ARCH="$(or $(ARCH),x86_64)" KERNEL_HEADERS="$(KERNEL_HEADERS)" sh tools/bootstrap-busybox.sh ./holypkg "$(INPUTS)" "$(or $(OUTPUT),out/busybox-bootstrap)"

check-bootstrap-busybox: holypkg
	sh tests/bootstrap-busybox.sh ./holypkg "$(or $(BUSYBOX_PACKAGE),out/busybox-bootstrap/busybox.holy)"

check-static-core:
	sh tests/static-core.sh "$(or $(STATIC_HOLYPKG),./holypkg)" "$(or $(BUSYBOX_PACKAGE),out/busybox-bootstrap/busybox.holy)" "$(DINIT_PACKAGE)"

.PHONY: check-libc-recovery
check-libc-recovery:
	@test -x "$(STATIC_HOLYPKG)" && test -x "$(MUSL_CC)" && test -f "$(MUSL_PACKAGE)" || { echo 'STATIC_HOLYPKG, MUSL_CC and MUSL_PACKAGE are required' >&2; exit 6; }
	HOLY_TEST_DYNAMIC_CHROOT=1 HOLY_TEST_STATIC_RECOVERY=1 GLIBC_PACKAGE="$(GLIBC_PACKAGE)" MUSL_CC="$(MUSL_CC)" MUSL_PACKAGE="$(MUSL_PACKAGE)" sh tests/dynamic.sh "$(STATIC_HOLYPKG)"

.PHONY: check-static-import
check-static-import:
	@test -x "$(STATIC_HOLYPKG)" || { echo 'STATIC_HOLYPKG is required' >&2; exit 6; }
	python3 tests/static-import.py "$(STATIC_HOLYPKG)"

.PHONY: check-recipe
check-recipe: holypkg
	python3 tests/recipe.py ./holypkg

.PHONY: check-evaluate
check-evaluate: holypkg
	python3 tests/evaluate.py ./holypkg

.PHONY: check-command-version
check-command-version: holypkg
	sh tests/command-version.sh ./holypkg

.PHONY: check-pkgbuild
check-pkgbuild: holypkg
	python3 tests/pkgbuild.py ./holypkg

.PHONY: check-void
check-void: holypkg
	python3 tests/void.py ./holypkg

.PHONY: check-aports
check-aports: holypkg
	python3 tests/aports.py ./holypkg

.PHONY: check-slackbuild
check-slackbuild: holypkg
	python3 tests/slackbuild.py ./holypkg

.PHONY: check-rpmspec
check-rpmspec: holypkg
	python3 tests/rpmspec.py ./holypkg

.PHONY: check-debsrc
check-debsrc: holypkg
	python3 tests/debsrc.py ./holypkg

.PHONY: check-gentoo
check-gentoo: holypkg
	python3 tests/gentoo.py ./holypkg

.PHONY: check-pacstall
check-pacstall: holypkg
	python3 tests/pacstall.py ./holypkg

.PHONY: check-flatpak
check-flatpak: holypkg
	python3 tests/flatpak.py ./holypkg

.PHONY: check-brew
check-brew: holypkg
	python3 tests/brew.py ./holypkg

.PHONY: check-guix
check-guix: holypkg
	python3 tests/guix.py ./holypkg

.PHONY: check-scoop
check-scoop: holypkg
	python3 tests/scoop.py ./holypkg

.PHONY: check-nix
check-nix: holypkg
	python3 tests/nix.py ./holypkg

.PHONY: check-eopkg
check-eopkg: holypkg
	python3 tests/eopkg.py ./holypkg

.PHONY: check-conflict
check-conflict: holypkg
	python3 tests/conflict.py ./holypkg

.PHONY: check-index
check-index: holypkg
	python3 tests/index.py ./holypkg

.PHONY: check-split
check-split: holypkg
	python3 tests/split.py ./holypkg

.PHONY: check-loader-search
check-loader-search: holypkg
	sh tests/loader-search.sh ./holypkg

.PHONY: check-debug
check-debug: holypkg
	python3 tests/debug.py ./holypkg

.PHONY: check-closure
check-closure: holypkg
	python3 tests/closure.py ./holypkg

.PHONY: check-cc
check-cc:
	@for cc in tcc gcc clang; do command -v $$cc >/dev/null || { echo "$$cc required for the compiler fixture" >&2; exit 6; }; done
	sh tests/compilers.sh

.PHONY: check-winget
check-winget: holypkg
	python3 tests/winget.py ./holypkg

.PHONY: check-rpm
check-rpm: holypkg tests/rpm-version-helper
	./tests/rpm-version-helper
	python3 tests/rpm-import.py ./holypkg
	python3 tests/rpm-md.py ./holypkg

tests/rpm-version-helper: tests/rpm-version.c backends/rpm-version.c backends/rpm-version.h .build-config
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOLV_CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic $(LDFLAGS) -o $@ tests/rpm-version.c backends/rpm-version.c $(SOLV_LIBS)

.PHONY: check-xbps-import
check-xbps-import: holypkg
	python3 tests/xbps-import.py ./holypkg

.PHONY: check-xbps-version
check-xbps-version: tests/xbps-version-helper
	./tests/xbps-version-helper

.PHONY: check-xbps-index
check-xbps-index: holypkg
	@command -v zstd >/dev/null && command -v openssl >/dev/null || { echo 'zstd and openssl required for XBPS fixture' >&2; exit 6; }
	python3 tests/xbps-index.py ./holypkg

tests/xbps-version-helper: tests/xbps-version.c backends/xbps-version.c backends/xbps-version.h .build-config
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic $(LDFLAGS) -o $@ tests/xbps-version.c backends/xbps-version.c

.PHONY: check-static-network
check-static-network:
	python3 tests/static-network.py "$(or $(STATIC_HOLYPKG),./holypkg)" "$(or $(BUSYBOX_PACKAGE),out/busybox-bootstrap/busybox.holy)" "$(or $(REPORT),out/static-network.json)"

.PHONY: static-deps static check-static-target
check-static-target:
	@test -x "$(STATIC_HOLYPKG)" && test -x "$(MUSL_CC)" || { echo 'STATIC_HOLYPKG and MUSL_CC are required' >&2; exit 6; }
	python3 tests/target.py "$(STATIC_HOLYPKG)" "$(or $(ARCH),x86_64)" "$(MUSL_CC)"

static-deps:
	ARCH="$(or $(ARCH),x86_64)" sh tools/static-deps.sh "$(INPUTS)" "$(or $(OUTPUT),out/static-deps)" "$(KERNEL_HEADERS)"

static:
	@test -n "$(STATIC_DEPS)" || { echo 'STATIC_DEPS must name the musl dependency prefix' >&2; exit 6; }
	@test -x "$(STATIC_DEPS)/bin/holy-musl-gcc" && grep -qx 'exit 0' "$(STATIC_DEPS)/build.record" || { echo 'static dependency build is incomplete' >&2; exit 6; }
	$(MAKE) clean
	$(MAKE) CC="$(STATIC_DEPS)/bin/holy-musl-gcc" CPPFLAGS="-isystem $(STATIC_DEPS)/include" RPM_CFLAGS= RPM_LIBS= RPMMD_CFLAGS= RPMMD_LIBS= SOLV_CFLAGS="-isystem $(STATIC_DEPS)/include" SOLV_LIBS="-lsolv -lz" LDFLAGS="-static -L$(STATIC_DEPS)/lib" LDLIBS="-Wl,--start-group -larchive -lelf -lcurl -lplist-2.0 -lssl -lcrypto -llz4 -lzstd -llzma -lbz2 -lz -leu -Wl,--end-group -lpthread -ldl" all

HOLY_OBJECTS = src/bwrap.o src/main.o src/config.o src/package.o src/verify.o src/fetch.o src/extract.o src/check.o src/script.o src/elf.o src/scan.o src/stage.o src/repo.o src/sign.o src/git.o src/preview.o src/deps.o src/provides.o src/cache.o src/state.o src/solve.o src/resolve.o src/install.o src/pack.o src/docs.o src/graph.o src/source.o src/change.o src/import.o src/appimage.o src/test.o src/trial.o src/up.o src/version.o src/run.o src/recipe.o src/sandbox.o src/evaluate.o src/image.o src/snap.o src/scoop.o src/artifact.o src/winget.o src/nix.o src/split.o src/eopkg.o src/conflict.o src/index.o src/keyring.o src/override.o backends/pkgbuild.o backends/shrecipe.o backends/voidsrc.o backends/aports.o backends/slackbuild.o backends/rpmspec.o backends/debsrc.o backends/gentoo.o backends/pacstall.o backends/flatpak.o backends/brew.o backends/guix.o backends/pacman.o backends/pacman-version.o backends/deb-version.o backends/apk-version.o backends/xbps-version.o backends/rpm-version.o backends/rpm-md.o backends/xbps.o backends/apk.o backends/apt.o backends/apt-release.o backends/apt-bind.o

holypkg: $(HOLY_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(SOLV_LIBS)

src/solve.o: src/solve.c $(wildcard src/*.h) .build-config
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOLV_CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic -c -o $@ $<

backends/rpm-version.o: backends/rpm-version.c backends/rpm-version.h .build-config
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOLV_CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic -c -o $@ $<

backends/%.o: backends/%.c $(wildcard backends/*.h) .build-config
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic -c -o $@ $<

src/%.o: src/%.c $(wildcard src/*.h) $(wildcard backends/*.h) .build-config
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic -c -o $@ $<

.PHONY: check-init
check-init: holy-init
	@./holy-init >/dev/null 2>&1; test $$? -eq 2

.PHONY: check-hooks
check-hooks: holypkg
	CC="$(CC)" sh tests/hooks.sh ./holypkg

check: check-pacman check-deb check-apt check-slackware check-apk check-xbps-import check-xbps-version check-xbps-index check-appimage check-snap check-run check-recipe check-evaluate check-command-version check-split check-debug check-pkgbuild check-void check-aports check-slackbuild check-rpmspec check-debsrc check-gentoo check-pacstall check-flatpak check-brew check-guix check-scoop check-winget check-nix check-eopkg check-conflict check-index check-closure check-loader-search check-slot-choice check-packages-page check-update-group check-qemu-copy check-plan-test check-override check-cc check-hooks check-apk-version check-apk-index check-apk-fetch check-native-version $(if $(RPM_LIBS),check-rpm) holypkg tests/resolution check-init check-solver check-install-payload check-install check-https check-git-source check-repo-closure
	./tests/resolution
	sh tests/config.sh ./holypkg
	sh tests/source.sh ./holypkg
	sh tests/source-instances.sh ./holypkg
	sh tests/package.sh ./holypkg
	sh tests/installed-scripts.sh ./holypkg
	sh tests/docs.sh
	sh tests/installed-docs.sh ./holypkg
	CC="$(CC)" sh tests/elf.sh ./holypkg
	sh tests/repo.sh ./holypkg
	sh tests/state.sh ./holypkg
	sh tests/sets.sh ./holypkg
	sh tests/add.sh ./holypkg
	sh tests/update.sh ./holypkg
	sh tests/up.sh ./holypkg
	sh tests/update-privileged.sh ./holypkg
	sh tests/update-group.sh ./holypkg
	sh tests/directories.sh ./holypkg
	python3 tests/hardlinks.py ./holypkg ./tests/install-helper
	python3 tests/hardlink-updates.py ./holypkg
	python3 tests/architecture.py ./holypkg
	sh tests/orphan.sh ./holypkg
	sh tests/dynamic.sh ./holypkg
	sh tests/resolve.sh ./holypkg ./tests/resolution
	sh tests/elf-resolve.sh ./holypkg ./tests/resolution
	sh tests/static.sh ./holypkg

.PHONY: check-pacman
check-pacman: holypkg
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic $(LDFLAGS) -o tests/pacman-helper tests/pacman.c backends/pacman.c backends/pacman-version.c
	./tests/pacman-helper
	python3 tests/import.py ./holypkg
	python3 tests/versions.py ./holypkg

.PHONY: check-deb
check-deb: holypkg
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic $(LDFLAGS) -o tests/deb-version-helper tests/deb-version.c backends/deb-version.c
	./tests/deb-version-helper
	python3 tests/import-deb.py ./holypkg

.PHONY: check-slackware
check-slackware: holypkg
	python3 tests/import-slackware.py ./holypkg

.PHONY: check-apk
check-apk: holypkg
	python3 tests/import-apk.py ./holypkg

.PHONY: check-apt
check-apt: holypkg
	python3 tests/apt.py ./holypkg

.PHONY: check-appimage
check-appimage: holypkg
	python3 tests/appimage.py ./holypkg

.PHONY: check-snap
check-snap: holypkg
	python3 tests/snap.py ./holypkg

.PHONY: check-apk-version
check-apk-version: tests/apk-version-helper
	python3 tests/apk-version.py ./tests/apk-version-helper

.PHONY: check-apk-index
check-apk-index: holypkg
	python3 tests/apk-index.py ./holypkg

.PHONY: check-apk-fetch
check-apk-fetch: holypkg
	python3 tests/apk-fetch.py ./holypkg

tests/apk-version-helper: tests/apk-version.c backends/apk-version.c backends/apk-version.h .build-config
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic $(LDFLAGS) -o $@ tests/apk-version.c backends/apk-version.c

.PHONY: check-native-version
check-native-version: tests/native-version-helper
	./tests/native-version-helper

tests/native-version-helper: tests/native-version.c src/version.c src/version.h .build-config
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic $(LDFLAGS) -o $@ tests/native-version.c src/version.c

check-fixtures: check

check-root: check-install-payload
	sh tests/installed-scripts.sh ./holypkg
	python3 tests/hardlinks.py ./holypkg ./tests/install-helper
	python3 tests/hardlink-updates.py ./holypkg
	python3 tests/architecture.py ./holypkg
	sh tests/state.sh ./holypkg
	sh tests/sets.sh ./holypkg
	sh tests/add.sh ./holypkg
	sh tests/update-privileged.sh ./holypkg
	sh tests/orphan.sh ./holypkg
	sh tests/slots.sh ./holypkg
	sh tests/dynamic.sh ./holypkg
	sh tests/static.sh ./holypkg

check-install: holyinstall holypkg
	sh tests/installer.sh ./holyinstall ./holypkg
	python3 tests/installer-disk.py ./holyinstall
	sh tests/install-source-stage.sh ./holypkg

.PHONY: check-install-vm
check-install-vm:
	@test -n "$(ISO)" && test -n "$(BOOT_PLAN)" || { echo 'ISO and BOOT_PLAN required' >&2; exit 6; }
	ARCH="$(or $(ARCH),x86_64)" ISO="$(ISO)" BOOT_PLAN="$(BOOT_PLAN)" REPORT_DIR="$(or $(REPORT_DIR),/tmp)" INSTALL_FIRMWARE="$(or $(INSTALL_FIRMWARE),$(if $(filter i686,$(ARCH)),bios,both))" UEFI_CODE="$(UEFI_CODE)" UEFI_VARS="$(UEFI_VARS)" python3 tests/install-vm.py

check-qemu:
	ARCH="$(ARCH)" ISO="$(or $(ISO),out/holy-$(ARCH).iso)" BOOT_PLAN="$(BOOT_PLAN)" QEMU_TIMEOUT="$(or $(QEMU_TIMEOUT),120)" sh tests/qemu.sh

.PHONY: check-qemu-copy
check-qemu-copy:
	python3 tests/qemu-copy.py

.PHONY: check-plan-test
check-plan-test:
	sh tests/plan-test.sh ./holypkg

.PHONY: check-override
check-override:
	sh tests/override.sh ./holypkg

.PHONY: check-update-group
check-update-group: holypkg
	sh tests/update-group.sh ./holypkg

.PHONY: check-root-trial
check-root-trial:
	sh tests/plan-test.sh ./holypkg --trial

check-qemu-gate:
	sh tests/qemu-gate.sh

check-hardware:
	HARDWARE_SCOPE="$(or $(HARDWARE_SCOPE),holy)" REPORT="$(or $(REPORT),out/hardware.json)" python3 tests/hardware.py

.PHONY: check-recovery-matrix
# the rollback contract is a configuration, so it is checked as one: two slots, a menu
# that shows both, a digest each path carries and a default that names the slot
check-rollback-config:
	sh tests/rollback-config.sh

# a repository that carries one name for several architectures must ask which slot, at
# the local mirror and through a registered source alike
check-slot-choice:
	sh tests/slot-choice.sh ./holypkg

# the published page is derived from the directory, so it cannot claim a package the
# index lacks or hide one it carries
check-packages-page:
	sh tests/packages-page.sh ./holypkg

.PHONY: check-image-docs
check-image-docs:
	sh tests/image-docs.sh "$(IMAGE_DIRECTORY)"

check-recovery-matrix:
	@test -n "$(REPORT)" && test -n "$(REPORTS)" || { echo 'REPORT and eight REPORTS paths are required' >&2; exit 6; }
	python3 tests/recovery-matrix.py --output "$(REPORT)" $(REPORTS)

check-https: holypkg
	@command -v python3 >/dev/null && command -v openssl >/dev/null || { echo 'python3 and openssl required for HTTPS fixture' >&2; exit 6; }
	sh tests/https.sh ./holypkg

check-install-payload: holypkg
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic -Isrc -o tests/install-helper tests/install.c src/install.c src/script.o src/elf.o src/change.c src/verify.c src/package.c src/stage.c src/config.c src/version.c backends/rpm-version.o $(LDFLAGS) -larchive -lcrypto -lelf $(SOLV_LIBS)
	sh tests/install.sh ./tests/install-helper ./holypkg
	sh tests/symlinks.sh ./holypkg
	sh tests/change.sh ./tests/install-helper ./holypkg

check-solver:
	@pkg-config --exists libsolv || { echo 'libsolv development files required' >&2; exit 6; }
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOLV_CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic -Isrc -o tests/solver tests/solver.c src/solve.c $(LDFLAGS) $(SOLV_LIBS)
	./tests/solver

man:
	@for page in $(MANPAGES); do groff -Tascii -man "$$page" > /dev/null || exit; done

llm.txt: $(MANPAGES) tools/docs.sh
	sh tools/docs.sh "$@" $(MANPAGES)

install: all llm.txt
	install -d "$(DESTDIR)$(PREFIX)/bin" "$(DESTDIR)$(PREFIX)/share/man/man5" "$(DESTDIR)$(PREFIX)/share/man/man7" "$(DESTDIR)$(PREFIX)/share/man/man8" "$(DESTDIR)$(PREFIX)/share/holy"
	install -m 755 holypkg holy-init holyinstall "$(DESTDIR)$(PREFIX)/bin/"
	@for page in $(MANPAGES); do install -m 644 "$$page" "$(DESTDIR)$(PREFIX)/share/man/man$${page##*.}/" || exit; done
	install -m 644 llm.txt "$(DESTDIR)$(PREFIX)/share/holy/llm.txt"

tests/resolution: tests/resolution.c $(filter-out src/main.o,$(HOLY_OBJECTS)) holypkg
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic $(LDFLAGS) -o $@ $< $(filter-out src/main.o,$(HOLY_OBJECTS)) $(LDLIBS) $(SOLV_LIBS)

clean:
	rm -f holy-init
	rm -f holyinstall src/disk.o
	rm -f holygetiso src/getiso.o
	rm -f .build-config .build-config.tmp .build-config.tmp.*
	rm -f holypkg tests/resolution tests/solver tests/install-helper tests/pacman-helper tests/deb-version-helper tests/apk-version-helper tests/xbps-version-helper tests/rpm-version-helper tests/native-version-helper $(HOLY_OBJECTS)
