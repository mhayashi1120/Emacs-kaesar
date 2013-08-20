Summary
========

AES (Rijndael) implementations for Emacs

Functions
=========

See following function doc-string:

- kaesar-encrypt-string
- kaesar-decrypt-string
- kaesar-encrypt-bytes
- kaesar-decrypt-bytes
- kaesar-encrypt
- kaesar-decrypt


Test
====

    M-x ert (tag kaesar)


    emacs -q -batch -eval "(byte-compile-file \"kaesar.el\")"
    emacs -q -batch -l kaesar.el -l kaesar-test.el -l Emacs-openssl-cipher/openssl-cipher.el -eval "(ert '(tag kaesar))"

