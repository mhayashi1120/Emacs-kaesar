EMACS = emacs

check:
	$(EMACS) -q -batch -eval "(byte-compile-file \"kaesar.el\")"; \
	$(EMACS) -q -batch -l kaesar.el -eval "(byte-compile-file \"kaesar-file.el\")"; \
	$(EMACS) -q -batch -l kaesar.el -eval "(byte-compile-file \"kaesar-mode.el\")"; \
	$(EMACS) -q -batch -l kaesar.el -l kaesar.elc -l kaesar-file.el -l kaesar-mode.el \
		-l Emacs-openssl-cipher/openssl-cipher.el -l kaesar-test.el \
		-eval "(ert-run-tests-batch-and-exit '(tag kaesar))";

clean:
	rm -f *.elc
