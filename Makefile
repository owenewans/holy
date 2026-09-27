CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2
LDFLAGS ?=
LDLIBS ?= -larchive -lcrypto -lelf -lcurl
PREFIX ?= /usr
DESTDIR ?=
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
all: holypkg

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
	$(MAKE) CC="$(STATIC_DEPS)/bin/holy-musl-gcc" CPPFLAGS="-isystem $(STATIC_DEPS)/include" SOLV_CFLAGS="-isystem $(STATIC_DEPS)/include" SOLV_LIBS="-lsolv -lz" LDFLAGS="-static -L$(STATIC_DEPS)/lib" LDLIBS="-Wl,--start-group -larchive -lelf -lcurl -lssl -lcrypto -llz4 -lz -leu -Wl,--end-group -lpthread -ldl" holypkg

holypkg: src/main.o src/config.o src/package.o src/verify.o src/fetch.o src/extract.o src/check.o src/elf.o src/scan.o src/stage.o src/repo.o src/preview.o src/deps.o src/provides.o src/cache.o src/state.o src/solve.o src/resolve.o src/install.o src/pack.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(SOLV_LIBS)

src/solve.o: src/solve.c $(wildcard src/*.h) .build-config
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOLV_CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic -c -o $@ $<

src/%.o: src/%.c $(wildcard src/*.h) .build-config
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic -c -o $@ $<

check: holypkg check-solver check-install-payload check-https
	sh tests/config.sh ./holypkg
	sh tests/package.sh ./holypkg
	sh tests/docs.sh
	CC="$(CC)" sh tests/elf.sh ./holypkg
	sh tests/repo.sh ./holypkg
	sh tests/state.sh ./holypkg
	sh tests/resolve.sh ./holypkg
	sh tests/static.sh ./holypkg

check-fixtures: check

check-root: check-install-payload
	sh tests/state.sh ./holypkg
	sh tests/static.sh ./holypkg

check-qemu:
	ARCH="$(ARCH)" ISO="$(or $(ISO),out/holy-$(ARCH).iso)" BOOT_PLAN="$(BOOT_PLAN)" QEMU_TIMEOUT="$(or $(QEMU_TIMEOUT),120)" sh tests/qemu.sh

check-qemu-gate:
	sh tests/qemu-gate.sh

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
	@for page in man/holy.conf.5 man/holypkg.8 man/holy-package.5; do groff -Tascii -man "$$page" > /dev/null || exit; done

llm.txt: man/holy.conf.5 man/holypkg.8 man/holy-package.5 tools/docs.sh
	sh tools/docs.sh "$@" man/holy.conf.5 man/holypkg.8 man/holy-package.5

install: holypkg llm.txt
	install -d "$(DESTDIR)$(PREFIX)/bin" "$(DESTDIR)$(PREFIX)/share/man/man5" "$(DESTDIR)$(PREFIX)/share/man/man8" "$(DESTDIR)$(PREFIX)/share/holy"
	install -m 755 holypkg "$(DESTDIR)$(PREFIX)/bin/holypkg"
	install -m 644 man/holy.conf.5 "$(DESTDIR)$(PREFIX)/share/man/man5/holy.conf.5"
	install -m 644 man/holy-package.5 "$(DESTDIR)$(PREFIX)/share/man/man5/holy-package.5"
	install -m 644 man/holypkg.8 "$(DESTDIR)$(PREFIX)/share/man/man8/holypkg.8"
	install -m 644 llm.txt "$(DESTDIR)$(PREFIX)/share/holy/llm.txt"

clean:
	rm -f .build-config .build-config.tmp
	rm -f holypkg tests/solver tests/install-helper src/main.o src/config.o src/package.o src/verify.o src/fetch.o src/extract.o src/check.o src/elf.o src/scan.o src/stage.o src/repo.o src/preview.o src/deps.o src/provides.o src/cache.o src/state.o src/solve.o src/resolve.o src/install.o src/pack.o
