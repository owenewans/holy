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

.PHONY: all check check-fixtures check-root check-qemu check-qemu-gate check-https check-solver check-install-payload bootstrap-busybox check-bootstrap-busybox check-static-core man
all: holypkg holy-init

holy-init: src/early-init.c .build-config
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic $(LDFLAGS) -o $@ $<

.PHONY: bootstrap-musl
bootstrap-musl: holypkg
	sh tools/bootstrap-musl.sh ./holypkg "$(INPUTS)" "$(or $(OUTPUT),out/musl-bootstrap)"

.PHONY: bootstrap-glibc check-bootstrap-glibc
bootstrap-glibc: holypkg
	sh tools/bootstrap-glibc.sh ./holypkg "$(INPUTS)" "$(or $(OUTPUT),out/glibc-bootstrap)"

check-bootstrap-glibc:
	@test "$$(id -u)" != 0 && test -f "$(or $(OUTPUT),out/glibc-bootstrap)/glibc.holy" || { echo 'ordinary user and completed glibc build required' >&2; exit 6; }
	$(MAKE) -C "$(or $(OUTPUT),out/glibc-bootstrap)/build" -j"$(or $(JOBS),2)" check

.PHONY: bootstrap-image
bootstrap-image: holypkg llm.txt
	ROOT_STORAGE="$(or $(ROOT_STORAGE),ram)" IMAGE_PROFILE="$(or $(IMAGE_PROFILE),dual-libc)" LIBC_BOOT_STATE="$(or $(LIBC_BOOT_STATE),present)" GLIBC_PACKAGE="$(GLIBC_PACKAGE)" MUSL_PACKAGE="$(MUSL_PACKAGE)" GLIBC_CC="$(or $(GLIBC_CC),gcc)" MUSL_CC="$(MUSL_CC)" sh tools/bootstrap-image.sh ./holypkg "$(STATIC_HOLYPKG)" "$(STATIC_CC)" "$(BUSYBOX_PACKAGE)" "$(DINIT_PACKAGE)" "$(MDEVD_PACKAGE)" "$(KERNEL_IMAGE)" "$(KERNEL_VERSION)" "$(LIMINE_DIR)" "$(OUTPUT)"

.PHONY: bootstrap-dinit check-bootstrap-dinit
.PHONY: bootstrap-mdevd check-bootstrap-mdevd
bootstrap-mdevd: holypkg
	sh tools/bootstrap-mdevd.sh ./holypkg "$(INPUTS)" "$(or $(OUTPUT),out/mdevd-bootstrap)"

check-bootstrap-mdevd: holypkg
	sh tests/bootstrap-mdevd.sh ./holypkg "$(or $(MDEVD_PACKAGE),out/mdevd-bootstrap/mdevd.holy)"

bootstrap-dinit: holypkg
	sh tools/bootstrap-dinit.sh ./holypkg "$(INPUTS)" "$(or $(OUTPUT),out/dinit-bootstrap)"

check-bootstrap-dinit: holypkg
	sh tests/bootstrap-dinit.sh ./holypkg "$(or $(DINIT_PACKAGE),out/dinit-bootstrap/dinit.holy)" "$(or $(BUSYBOX_PACKAGE),out/busybox-bootstrap/busybox.holy)"

bootstrap-busybox: holypkg
	sh tools/bootstrap-busybox.sh ./holypkg "$(INPUTS)" "$(or $(OUTPUT),out/busybox-bootstrap)"

check-bootstrap-busybox: holypkg
	sh tests/bootstrap-busybox.sh ./holypkg "$(or $(BUSYBOX_PACKAGE),out/busybox-bootstrap/busybox.holy)"

check-static-core:
	sh tests/static-core.sh "$(or $(STATIC_HOLYPKG),./holypkg)" "$(or $(BUSYBOX_PACKAGE),out/busybox-bootstrap/busybox.holy)" "$(DINIT_PACKAGE)"

.PHONY: check-libc-recovery
check-libc-recovery:
	@test -x "$(STATIC_HOLYPKG)" && test -x "$(MUSL_CC)" && test -f "$(MUSL_PACKAGE)" || { echo 'STATIC_HOLYPKG, MUSL_CC and MUSL_PACKAGE are required' >&2; exit 6; }
	HOLY_TEST_DYNAMIC_CHROOT=1 HOLY_TEST_STATIC_RECOVERY=1 GLIBC_PACKAGE="$(GLIBC_PACKAGE)" MUSL_CC="$(MUSL_CC)" MUSL_PACKAGE="$(MUSL_PACKAGE)" sh tests/dynamic.sh "$(STATIC_HOLYPKG)"

.PHONY: check-static-network
check-static-network:
	python3 tests/static-network.py "$(or $(STATIC_HOLYPKG),./holypkg)" "$(or $(BUSYBOX_PACKAGE),out/busybox-bootstrap/busybox.holy)" "$(or $(REPORT),out/static-network.json)"

.PHONY: static-deps static
static-deps:
	sh tools/static-deps.sh "$(INPUTS)" "$(or $(OUTPUT),out/static-deps)" "$(KERNEL_HEADERS)"

static:
	@test -n "$(STATIC_DEPS)" || { echo 'STATIC_DEPS must name the musl dependency prefix' >&2; exit 6; }
	@test -x "$(STATIC_DEPS)/bin/holy-musl-gcc" && grep -qx 'exit 0' "$(STATIC_DEPS)/build.record" || { echo 'static dependency build is incomplete' >&2; exit 6; }
	$(MAKE) clean
	$(MAKE) CC="$(STATIC_DEPS)/bin/holy-musl-gcc" CPPFLAGS="-isystem $(STATIC_DEPS)/include" SOLV_CFLAGS="-isystem $(STATIC_DEPS)/include" SOLV_LIBS="-lsolv -lz" LDFLAGS="-static -L$(STATIC_DEPS)/lib" LDLIBS="-Wl,--start-group -larchive -lelf -lcurl -lssl -lcrypto -llz4 -lz -leu -Wl,--end-group -lpthread -ldl" all

HOLY_OBJECTS = src/main.o src/config.o src/package.o src/verify.o src/fetch.o src/extract.o src/check.o src/elf.o src/scan.o src/stage.o src/repo.o src/preview.o src/deps.o src/provides.o src/cache.o src/state.o src/solve.o src/resolve.o src/install.o src/pack.o src/docs.o src/graph.o src/source.o

holypkg: $(HOLY_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(SOLV_LIBS)

src/solve.o: src/solve.c $(wildcard src/*.h) .build-config
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOLV_CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic -c -o $@ $<

src/%.o: src/%.c $(wildcard src/*.h) .build-config
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic -c -o $@ $<

.PHONY: check-init
check-init: holy-init
	@./holy-init >/dev/null 2>&1; test $$? -eq 2

check: holypkg tests/resolution check-init check-solver check-install-payload check-https
	./tests/resolution
	sh tests/config.sh ./holypkg
	sh tests/source.sh ./holypkg
	sh tests/package.sh ./holypkg
	sh tests/docs.sh
	sh tests/installed-docs.sh ./holypkg
	CC="$(CC)" sh tests/elf.sh ./holypkg
	sh tests/repo.sh ./holypkg
	sh tests/state.sh ./holypkg
	sh tests/sets.sh ./holypkg
	sh tests/orphan.sh ./holypkg
	sh tests/dynamic.sh ./holypkg
	sh tests/resolve.sh ./holypkg ./tests/resolution
	sh tests/elf-resolve.sh ./holypkg ./tests/resolution
	sh tests/static.sh ./holypkg

check-fixtures: check

check-root: check-install-payload
	sh tests/state.sh ./holypkg
	sh tests/sets.sh ./holypkg
	sh tests/orphan.sh ./holypkg
	sh tests/dynamic.sh ./holypkg
	sh tests/static.sh ./holypkg

check-qemu:
	ARCH="$(ARCH)" ISO="$(or $(ISO),out/holy-$(ARCH).iso)" BOOT_PLAN="$(BOOT_PLAN)" QEMU_TIMEOUT="$(or $(QEMU_TIMEOUT),120)" sh tests/qemu.sh

check-qemu-gate:
	sh tests/qemu-gate.sh

.PHONY: check-recovery-matrix
check-recovery-matrix:
	@test -n "$(REPORT)" && test -n "$(REPORTS)" || { echo 'REPORT and eight REPORTS paths are required' >&2; exit 6; }
	python3 tests/recovery-matrix.py --output "$(REPORT)" $(REPORTS)

check-https: holypkg
	@command -v python3 >/dev/null && command -v openssl >/dev/null || { echo 'python3 and openssl required for HTTPS fixture' >&2; exit 6; }
	sh tests/https.sh ./holypkg

check-install-payload: holypkg
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic -Isrc -o tests/install-helper tests/install.c src/install.c src/verify.c src/package.c src/stage.c src/config.c $(LDFLAGS) -larchive -lcrypto
	sh tests/install.sh ./tests/install-helper ./holypkg
	sh tests/symlinks.sh ./holypkg

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
	install -m 755 holypkg holy-init "$(DESTDIR)$(PREFIX)/bin/"
	@for page in $(MANPAGES); do install -m 644 "$$page" "$(DESTDIR)$(PREFIX)/share/man/man$${page##*.}/" || exit; done
	install -m 644 llm.txt "$(DESTDIR)$(PREFIX)/share/holy/llm.txt"

tests/resolution: tests/resolution.c $(filter-out src/main.o,$(HOLY_OBJECTS)) holypkg
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic $(LDFLAGS) -o $@ $< $(filter-out src/main.o,$(HOLY_OBJECTS)) $(LDLIBS) $(SOLV_LIBS)

clean:
	rm -f holy-init
	rm -f .build-config .build-config.tmp
	rm -f holypkg tests/resolution tests/solver tests/install-helper $(HOLY_OBJECTS)
