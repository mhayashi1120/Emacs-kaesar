VERSION = 0.1.0

RELEASE_FILES = cipher-pkg.el \
	cipher/aes-file.el cipher/aes-mode.el cipher/aes.el \
	cipher/rsa.el

BASE_NAME = cipher-$(VERSION)
ARCHIVE_FILE = $(BASE_NAME).tar

archive: prepare
	mkdir -p /tmp/$(BASE_NAME); \
	cp --parents $(RELEASE_FILES) /tmp/$(BASE_NAME); \
	tar cf $(ARCHIVE_FILE) -C /tmp $(BASE_NAME);

prepare:
	rm -rf /tmp/$(BASE_NAME)


