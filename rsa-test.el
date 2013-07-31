(require 'rsa)
(require 'ert)


(defun rsa-test--check-enc/dec (key data)
  (should (equal
           (rsa--decrypt-bytes
            (vconcat
             (rsa--encrypt-bytes data key))
            key) data)))


(defun rsa-test--random-string ()
  (loop repeat (+ (random 8) 2)
        collect (random 256) into res
        finally return (apply 'unibyte-string res)))

(defun rsa-test--read-data (file)
  (with-temp-buffer
    (let ((coding-system-for-write 'binary))
      (write-region C nil file)
      (buffer-string))))

(defun rsa-test--openssl-genrsa ()
  (let ((key (make-temp-file "rsa-test-")))
    (with-temp-buffer
      (call-process "openssl" nil t nil "genrsa" "-out" key)
      (buffer-string))
    key))

(defun rsa-test--openssl-encrypt (keyfile data)
  (rsa-test--call-openssl-rsautl
   data "-encrypt" "-inkey" keyfile))

(defun rsa-test--openssl-decrypt (keyfile data)
  (rsa-test--call-openssl-rsautl
   data "-decrypt" "-inkey" keyfile))

;;TODO
(defun rsa-test--openssl-sign (keyfile data)
  (rsa-test--call-openssl-rsautl
   data "-sign" "-inkey" keyfile))

;;TODO
(defun rsa-test--openssl-verify (keyfile data)
  (rsa-test--call-openssl-rsautl
   data "-verify" "-inkey" keyfile))

(defun rsa-test--call-openssl-rsautl (data &rest args)
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (insert data)
    (apply 'call-process-region
           (point-min) (point-max)
           "openssl" t t nil "rsautl" args)
    (buffer-string)))

(defvar rsa-test--key-length 256)
(defvar rsa-test--repeat 10)

(ert-deftest rsa-test--general ()
  ""
  :tags '(rsa)
  (loop repeat rsa-test--repeat
        do (let* ((key (rsa-generate-key rsa-test--key-length "A"))
                  (public-key (rsa-key:export-public key))
                  (M (rsa-test--random-string))
                  (C (rsa-encrypt-bytes public-key M))
                  (M2 (rsa-decrypt-bytes key C)))
             (should (equal M2 M)))))

(ert-deftest rsa-test--sign ()
  ""
  :tags '(rsa)
  (loop repeat rsa-test--repeat
        do (let* ((key (rsa-generate-key rsa-test--key-length "A"))
                  (public-key (rsa-key:export-public key))
                  (M (rsa-test--random-string))
                  (hash (md5 M))
                  (digest (rsa--hex-to-bytes hash))
                  (C (rsa-sign-hash key digest)))
             (rsa-verify-hash public-key C digest))))

(ert-deftest rsa-test--openssl-mutual ()
  ""
  :tags '(rsa)
  (loop repeat rsa-test--repeat
        do (let* ((keyfile (rsa-test--openssl-genrsa)) ;TODO generating key...
                  (key (rsa-openssh-load-key keyfile))
                  (M "hogehoge")
                  (Ce (rsa-encrypt-bytes key M))
                  (Co (rsa-test--openssl-encrypt keyfile M))
                  (Me (rsa-decrypt-bytes key Co))
                  (Mo (rsa-test--openssl-decrypt keyfile Ce)))
             (should (equal M Me))
             (should (equal M Mo))
             (delete-file keyfile))))

(ert-deftest rsa-test--keyfile-loading ()
  ""
  :tags '(rsa)
  (loop repeat rsa-test--repeat
        do (let ((keylen rsa-test--key-length)
                 (secfile (make-temp-file "rsa-test-"))
                 (pubfile (make-temp-file "rsa-test-")))
             (shell-command-to-string (format "openssl genrsa %d > %s" keylen secfile))
             (shell-command-to-string (format "openssl rsa -in %s -pubout > %s" secfile pubfile))
             (let ((seckey (rsa-openssh-load-key secfile))
                   (pubkey (rsa-openssh-load-pubkey pubfile)))
               (should (equal (rsa-key:N seckey) (rsa-key:N pubkey)))
               (should (equal (rsa-key:E seckey) (rsa-key:E pubkey)))
               (let* ((M "a")
                      (C (rsa-encrypt-bytes pubkey M))
                      (M2 (rsa-decrypt-bytes seckey C)))
                 (should (equal M M2))))
             (delete-file secfile)
             (delete-file pubfile))))

;;TODO loop by padding method
(ert-deftest rsa-test--padding ()
  ""
  :tags '(rsa)
  (loop repeat rsa-test--repeat
        do
        (loop for m in '(pkcs sslv23 oaep)
              do (let* ((rsa-padding-method m)
                        (s (rsa-test--random-string))
                        (padded (rsa--padding-add s 256))
                        (s2 (rsa--padding-remove padded)))
                   (should (equal s s2))))))


(provide 'rsa-test)
