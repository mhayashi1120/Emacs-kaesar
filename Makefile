VERSION = 0.1.0

RELEASE_FILES =  \
	kaesar-file.el kaesar-mode.el kaesar.el \

BASE_NAME = kaesar-$(VERSION)
ARCHIVE_FILE = $(BASE_NAME).tar

archive: prepare
	mkdir -p /tmp/$(BASE_NAME); \
	cp --parents $(RELEASE_FILES) /tmp/$(BASE_NAME); \
	tar cf $(ARCHIVE_FILE) -C /tmp $(BASE_NAME);

prepare:
	rm -rf /tmp/$(BASE_NAME)


