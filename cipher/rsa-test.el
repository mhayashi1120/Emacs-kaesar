(require 'cipher/aes)
(require 'openssl-cipher nil t)
(require 'ert)


(defun cipher/rsa-test--check-enc/dec (key data)
  (should (equal
           (cipher/rsa--decrypt-bytes
            (vconcat
             (cipher/rsa--encrypt-bytes data key))
            key) data)))


(defun cipher/rsa-test--random-string ()
  (loop repeat (+ (random 8) 2)
        collect (random 256) into res
        finally return (apply 'unibyte-string res)))

(ert-deftest cipher/rsa-test--general ()
  ""
  :tags '(cipher/rsa)
  (loop repeat 10
        do (let* ((key (cipher/rsa-generate-key "A" 20))
                  (public-key (cipher/rsa-key:export-public key))
                  (M (cipher/rsa-test--random-string))
                  (C (cipher/rsa--encrypt-bytes M public-key))
                  (M2 (cipher/rsa--decrypt-bytes C key))
             ))))


(provide 'cipher/rsa-test)
