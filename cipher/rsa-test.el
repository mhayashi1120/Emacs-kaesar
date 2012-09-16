(require 'cipher/rsa)
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

(defun cipher/rsa-test--read-data (file)
  (with-temp-buffer
    (let ((coding-system-for-write 'binary))
      (write-region C nil file)
      (buffer-string))))

(defun cipher/rsa-test--openssl-genrsa ()
  (let ((key (make-temp-file "rsa-test-")))
    (with-temp-buffer
      (call-process "openssl" nil t nil "genrsa" "-out" key)
      (buffer-string))
    key))

(defun cipher/rsa-test--openssl-encrypt (keyfile data)
  (cipher/rsa-test--call-openssl-rsautl
   data "-encrypt" "-inkey" keyfile))

(defun cipher/rsa-test--openssl-decrypt (keyfile data)
  (cipher/rsa-test--call-openssl-rsautl
   data "-decrypt" "-inkey" keyfile))

;;TODO
(defun cipher/rsa-test--openssl-sign (keyfile data)
  (cipher/rsa-test--call-openssl-rsautl
   data "-sign" "-inkey" keyfile))

;;TODO
(defun cipher/rsa-test--openssl-verify (keyfile data)
  (cipher/rsa-test--call-openssl-rsautl
   data "-verify" "-inkey" keyfile))

(defun cipher/rsa-test--call-openssl-rsautl (data &rest args)
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (insert data)
    (apply 'call-process-region 
           (point-min) (point-max)
           "openssl" t t nil "rsautl" args)
    (buffer-string)))

(defvar cipher/rsa-test--key-length 256)
(defvar cipher/rsa-test--repeat 10)

(ert-deftest cipher/rsa-test--general ()
  ""
  :tags '(cipher/rsa)
  (loop repeat cipher/rsa-test--repeat
        do (let* ((key (cipher/rsa-generate-key "A" cipher/rsa-test--key-length))
                  (public-key (cipher/rsa-key:export-public key))
                  (M (cipher/rsa-test--random-string))
                  (C (cipher/rsa-encrypt-bytes public-key M))
                  (M2 (cipher/rsa-decrypt-bytes key C)))
             (should (equal M2 M)))))

(ert-deftest cipher/rsa-test--sign ()
  ""
  :tags '(cipher/rsa)
  (loop repeat cipher/rsa-test--repeat
        do (let* ((key (cipher/rsa-generate-key "A" cipher/rsa-test--key-length))
                  (public-key (cipher/rsa-key:export-public key))
                  (M (cipher/rsa-test--random-string))
                  ;; 256 bit key accept only 21 byte
                  (hash (substring (md5 M) 0 21))
                  (C (cipher/rsa-sign-hash key hash)))
             (cipher/rsa-verify-hash public-key C hash))))

(ert-deftest cipher/rsa-test--openssl-mutual ()
  ""
  :tags '(cipher/rsa)
  (loop repeat cipher/rsa-test--repeat
        do (let* ((keyfile (cipher/rsa-test--openssl-genrsa)) ;TODO generating key...
                  (key (cipher/rsa-openssh-load-key keyfile))
                  (M "hogehoge")
                  (Ce (cipher/rsa-encrypt-bytes key M))
                  (Co (cipher/rsa-test--openssl-encrypt keyfile M))
                  (Me (cipher/rsa-decrypt-bytes key Co))
                  (Mo (cipher/rsa-test--openssl-decrypt keyfile Ce)))
             (should (equal M Me))
             (should (equal M Mo)))))

(ert-deftest cipher/rsa-test--keyfile-loading ()
  ""
  :tags '(cipher/rsa)
  (loop repeat cipher/rsa-test--repeat
        do (let ((keylen cipher/rsa-test--key-length)
                 (secfile (make-temp-file "rsa-test-"))
                 (pubfile (make-temp-file "rsa-test-")))
             (shell-command-to-string (format "openssl genrsa %d > %s" keylen secfile))
             (shell-command-to-string (format "openssl rsa -in %s -pubout > %s" secfile pubfile))
             (let ((seckey (cipher/rsa-openssh-load-key secfile))
                   (pubkey (cipher/rsa-openssh-load-pubkey pubfile)))
               (should (equal (cipher/rsa-key:N seckey) (cipher/rsa-key:N pubkey)))
               (should (equal (cipher/rsa-key:E seckey) (cipher/rsa-key:E pubkey)))
               (let* ((M "a")
                      (C (cipher/rsa-encrypt-bytes pubkey M))
                      (M2 (cipher/rsa-decrypt-bytes seckey C)))
                 (should (equal M M2)))))))

(provide 'cipher/rsa-test)
