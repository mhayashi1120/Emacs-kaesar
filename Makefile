check:
	emacs -q -batch -eval "(byte-compile-file \"kaesar.el\")"; \
	emacs -q -batch -l kaesar.el -l kaesar-test.el -l Emacs-openssl-cipher/openssl-cipher.el -eval "(ert '(tag kaesar))"
