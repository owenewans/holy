CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2
LDFLAGS ?=
LDLIBS ?= -larchive -lcrypto
PREFIX ?= /usr
DESTDIR ?=

.PHONY: all check check-fixtures man
all: holypkg

holypkg: src/main.o src/config.o src/package.o src/verify.o src/fetch.o src/extract.o src/check.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

src/%.o: src/%.c src/config.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c99 -Wall -Wextra -Werror -pedantic -c -o $@ $<

check: holypkg
	sh tests/config.sh ./holypkg
	sh tests/package.sh ./holypkg
	sh tests/docs.sh

check-fixtures: check

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
	rm -f holypkg src/main.o src/config.o src/package.o src/verify.o src/fetch.o src/extract.o src/check.o
