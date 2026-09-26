CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2
LDFLAGS ?=
LDLIBS ?= -larchive -lcrypto -lelf
PREFIX ?= /usr
DESTDIR ?=
SOLV_CFLAGS ?= $(patsubst -I%,-isystem %,$(shell pkg-config --cflags-only-I libsolv 2>/dev/null)) $(shell pkg-config --cflags-only-other libsolv 2>/dev/null)
SOLV_LIBS ?= $(shell pkg-config --libs libsolv 2>/dev/null) -lz

.PHONY: all check check-fixtures check-solver man
all: holypkg

holypkg: src/main.o src/config.o src/package.o src/verify.o src/fetch.o src/extract.o src/check.o src/elf.o src/scan.o src/stage.o src/repo.o src/preview.o src/deps.o src/provides.o src/cache.o src/state.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

src/%.o: src/%.c src/config.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic -c -o $@ $<

check: holypkg check-solver
	sh tests/config.sh ./holypkg
	sh tests/package.sh ./holypkg
	sh tests/docs.sh
	CC="$(CC)" sh tests/elf.sh ./holypkg
	sh tests/repo.sh ./holypkg
	sh tests/state.sh ./holypkg

check-fixtures: check

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
	rm -f holypkg tests/solver src/main.o src/config.o src/package.o src/verify.o src/fetch.o src/extract.o src/check.o src/elf.o src/scan.o src/stage.o src/repo.o src/preview.o src/deps.o src/provides.o src/cache.o src/state.o
