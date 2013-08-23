check:
	emacs -q -batch -eval "(byte-compile-file \"kaesar.el\")"; \
	emacs -q -batch -l kaesar.el -l kaesar.elc -l Emacs-openssl-cipher/openssl-cipher.el -l kaesar-test.el \
		-eval "(ert-run-tests-batch-and-exit '(tag kaesar))"

clean:
	rm -f kaesar.elc
