CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2
LDFLAGS ?=
LDLIBS ?= -larchive -lcrypto -lelf -lcurl
PREFIX ?= /usr
DESTDIR ?=
MANPAGES = $(wildcard man/*.[578])
SOLV_CFLAGS ?= $(patsubst -I%,-isystem %,$(shell pkg-config --cflags-only-I libsolv 2>/dev/null)) $(shell pkg-config --cflags-only-other libsolv 2>/dev/null)
SOLV_LIBS ?= $(shell pkg-config --libs libsolv 2>/dev/null) -lz

.PHONY: force-build-config
.build-config: force-build-config
	$(file >$@.tmp,CC=$(CC))
	$(file >>$@.tmp,CPPFLAGS=$(CPPFLAGS))
	$(file >>$@.tmp,CFLAGS=$(CFLAGS))
	$(file >>$@.tmp,LDFLAGS=$(LDFLAGS))
	$(file >>$@.tmp,LDLIBS=$(LDLIBS))
	$(file >>$@.tmp,SOLV_CFLAGS=$(SOLV_CFLAGS))
	$(file >>$@.tmp,SOLV_LIBS=$(SOLV_LIBS))
	@cmp -s "$@.tmp" "$@" || mv "$@.tmp" "$@"
	@rm -f "$@.tmp"

.DEFAULT_GOAL := all

.PHONY: all check check-fixtures check-root check-qemu check-qemu-gate check-https check-solver check-install-payload check-install bootstrap-busybox check-bootstrap-busybox check-static-core man
all: holypkg holy-init holyinstall

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
	ARCH="$(or $(ARCH),x86_64)" ROOT_STORAGE="$(or $(ROOT_STORAGE),ram)" IMAGE_PROFILE="$(or $(IMAGE_PROFILE),dual-libc)" LIBC_BOOT_STATE="$(or $(LIBC_BOOT_STATE),present)" INSTALL_TEST="$(or $(INSTALL_TEST),0)" INSTALL_FIRMWARE="$(or $(INSTALL_FIRMWARE),both)" STORAGE_TOOLS_PACKAGE="$(STORAGE_TOOLS_PACKAGE)" DOAS_PACKAGE="$(DOAS_PACKAGE)" UEFI_CODE="$(UEFI_CODE)" UEFI_VARS="$(UEFI_VARS)" NETWORK_RECOVERY="$(or $(NETWORK_RECOVERY),off)" GLIBC_PACKAGE="$(GLIBC_PACKAGE)" MUSL_PACKAGE="$(MUSL_PACKAGE)" GLIBC_CC="$(or $(GLIBC_CC),gcc)" MUSL_CC="$(MUSL_CC)" STATIC_HOLYINSTALL="$(STATIC_HOLYINSTALL)" sh tools/bootstrap-image.sh ./holypkg "$(STATIC_HOLYPKG)" "$(STATIC_CC)" "$(BUSYBOX_PACKAGE)" "$(DINIT_PACKAGE)" "$(MDEVD_PACKAGE)" "$(KERNEL_IMAGE)" "$(KERNEL_VERSION)" "$(LIMINE_DIR)" "$(OUTPUT)"

.PHONY: bootstrap-storage
bootstrap-storage: holypkg
	sh tools/bootstrap-storage.sh ./holypkg "$(UTIL_LINUX_SOURCE)" "$(DOSFSTOOLS_SOURCE)" "$(E2FSPROGS_SOURCE)" "$(LIMINE_BINARY)" "$(STATIC_PREFIX)" "$(or $(OUTPUT),out/storage-bootstrap)"

.PHONY: check-bootstrap-storage
check-bootstrap-storage: holypkg
	sh tests/bootstrap-storage.sh ./holypkg "$(or $(STORAGE_TOOLS_PACKAGE),out/storage-bootstrap/holy-storage-tools.holy)"

.PHONY: bootstrap-doas
bootstrap-doas: holypkg
	sh tools/bootstrap-doas.sh ./holypkg "$(DOAS_SOURCE)" "$(STATIC_PREFIX)" "$(or $(OUTPUT),out/doas-bootstrap)"

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
	$(MAKE) CC="$(STATIC_DEPS)/bin/holy-musl-gcc" CPPFLAGS="-isystem $(STATIC_DEPS)/include" SOLV_CFLAGS="-isystem $(STATIC_DEPS)/include" SOLV_LIBS="-lsolv -lz" LDFLAGS="-static -L$(STATIC_DEPS)/lib" LDLIBS="-Wl,--start-group -larchive -lelf -lcurl -lssl -lcrypto -llz4 -lzstd -llzma -lbz2 -lz -leu -Wl,--end-group -lpthread -ldl" all

HOLY_OBJECTS = src/main.o src/config.o src/package.o src/verify.o src/fetch.o src/extract.o src/check.o src/elf.o src/scan.o src/stage.o src/repo.o src/preview.o src/deps.o src/provides.o src/cache.o src/state.o src/solve.o src/resolve.o src/install.o src/pack.o src/docs.o src/graph.o src/source.o src/change.o src/import.o backends/pacman.o backends/pacman-version.o

holypkg: $(HOLY_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(SOLV_LIBS)

src/solve.o: src/solve.c $(wildcard src/*.h) .build-config
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOLV_CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic -c -o $@ $<

backends/%.o: backends/%.c $(wildcard backends/*.h) .build-config
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic -c -o $@ $<

src/%.o: src/%.c $(wildcard src/*.h) $(wildcard backends/*.h) .build-config
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic -c -o $@ $<

.PHONY: check-init
check-init: holy-init
	@./holy-init >/dev/null 2>&1; test $$? -eq 2

check: check-pacman holypkg tests/resolution check-init check-solver check-install-payload check-install check-https
	./tests/resolution
	sh tests/config.sh ./holypkg
	sh tests/source.sh ./holypkg
	sh tests/source-instances.sh ./holypkg
	sh tests/package.sh ./holypkg
	sh tests/docs.sh
	sh tests/installed-docs.sh ./holypkg
	CC="$(CC)" sh tests/elf.sh ./holypkg
	sh tests/repo.sh ./holypkg
	sh tests/state.sh ./holypkg
	sh tests/sets.sh ./holypkg
	sh tests/update.sh ./holypkg
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

check-fixtures: check

check-root: check-install-payload
	python3 tests/hardlinks.py ./holypkg ./tests/install-helper
	python3 tests/hardlink-updates.py ./holypkg
	python3 tests/architecture.py ./holypkg
	sh tests/state.sh ./holypkg
	sh tests/sets.sh ./holypkg
	sh tests/orphan.sh ./holypkg
	sh tests/dynamic.sh ./holypkg
	sh tests/static.sh ./holypkg

check-install: holyinstall holypkg
	sh tests/installer.sh ./holyinstall ./holypkg
	python3 tests/installer-disk.py ./holyinstall

.PHONY: check-install-vm
check-install-vm:
	@test -n "$(ISO)" && test -n "$(BOOT_PLAN)" || { echo 'ISO and BOOT_PLAN required' >&2; exit 6; }
	ARCH=x86_64 ISO="$(ISO)" BOOT_PLAN="$(BOOT_PLAN)" REPORT_DIR="$(or $(REPORT_DIR),/tmp)" INSTALL_FIRMWARE="$(or $(INSTALL_FIRMWARE),both)" UEFI_CODE="$(UEFI_CODE)" UEFI_VARS="$(UEFI_VARS)" python3 tests/install-vm.py

check-qemu:
	ARCH="$(ARCH)" ISO="$(or $(ISO),out/holy-$(ARCH).iso)" BOOT_PLAN="$(BOOT_PLAN)" QEMU_TIMEOUT="$(or $(QEMU_TIMEOUT),120)" sh tests/qemu.sh

check-qemu-gate:
	sh tests/qemu-gate.sh

.PHONY: check-recovery-matrix
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
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic -Isrc -o tests/install-helper tests/install.c src/install.c src/change.c src/verify.c src/package.c src/stage.c src/config.c $(LDFLAGS) -larchive -lcrypto
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
	rm -f .build-config .build-config.tmp
	rm -f holypkg tests/resolution tests/solver tests/install-helper tests/pacman-helper $(HOLY_OBJECTS)
