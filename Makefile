EMACS = emacs

check: compile
	$(EMACS) -q -batch -l kaesar.el -l kaesar.elc -l kaesar-file.el -l kaesar-mode.el \
		-l Emacs-openssl-cipher/openssl-cipher.el -l kaesar-test.el \
		-f ert-run-tests-batch-and-exit

compile:
	$(EMACS) --version
	$(EMACS) -q -batch -L . -f batch-byte-compile kaesar.el kaesar-file.el kaesar-mode.el

clean:
	rm -f *.elc
