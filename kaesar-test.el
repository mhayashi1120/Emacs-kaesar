(require 'kaesar)
(require 'kaesar-file)
(require 'kaesar-mode)
(require 'kaesar-testutil)
(require 'openssl-cipher)
(require 'ert)

(defun kaesar-test---random-bytes ()
  (let ((s (make-string (random 200) ?\000)))
    (cl-loop for i from 0 below (length s)
             do (aset s i (random 256)))
    s))

(defun kaesar-test---openssl-key&iv (algorithm pass)
  (let ((key&iv (shell-command-to-string
                 (format "openssl %s -e -md md5 -pass pass:%s -P -nosalt" algorithm pass))))
    (when (string-match "^key *=\\(.*\\)\\(?:\niv *=\\(.*\\)\\)?" key&iv)
      (list (match-string 1 key&iv) (or (match-string 2 key&iv) "")))))

(defun kaesar-test-enc/dec (raw-bytes &optional algorithm)
  (kaesar-test-should raw-bytes
    (let ((kaesar-password (copy-sequence "d")))
      (kaesar-decrypt-bytes
       (let ((kaesar-password (copy-sequence "d")))
         (kaesar-encrypt-bytes raw-bytes algorithm))
       algorithm))))

(defun kaesar-test---block-random-test ()
  (let* ((bytes (kaesar-test---random-bytes))
         results)

    (let ((openssl-cipher-password (copy-sequence "d"))
          (kaesar-password (copy-sequence "d")))
      (setq results (openssl-cipher-decrypt-unibytes (kaesar-encrypt-bytes bytes)))
      (should (equal results bytes)))

    (let ((openssl-cipher-password (copy-sequence "d"))
          (kaesar-password (copy-sequence "d")))
      (setq results (kaesar-decrypt-bytes (openssl-cipher-encrypt-unibytes bytes)))
      (should (equal results bytes)))))

(ert-deftest kaesar-test--openssl-compatibility ()
  :tags '(kaesar)

  (kaesar-test-should (kaesar-test---openssl-key&iv "aes-128-cbc" "d")
    (kaesar--with-algorithm "aes-128-cbc"
      (cl-destructuring-bind (key iv) (kaesar--password-to-key (vconcat "d"))
        (list (kaesar-test---unibytes-to-hex key) (kaesar-test---unibytes-to-hex iv)))))

  (kaesar-test-should (kaesar-test---openssl-key&iv "aes-128-ecb" "d")
    (kaesar--with-algorithm "aes-128-ecb"
      (cl-destructuring-bind (key iv) (kaesar--password-to-key (vconcat "d"))
        (list (kaesar-test---unibytes-to-hex key) (kaesar-test---unibytes-to-hex iv)))))

  (kaesar-test-should (kaesar-test---openssl-key&iv "aes-256-ecb" "pass")
    (kaesar--with-algorithm "aes-256-ecb"
      (cl-destructuring-bind (key iv) (kaesar--password-to-key (vconcat "pass"))
        (list (kaesar-test---unibytes-to-hex key) (kaesar-test---unibytes-to-hex iv)))))

  (kaesar-test-should (kaesar-test---openssl-key&iv "aes-256-cbc" "pass")
    (kaesar--with-algorithm "aes-256-cbc"
      (cl-destructuring-bind (key iv) (kaesar--password-to-key (vconcat "pass"))
        (list (kaesar-test---unibytes-to-hex key) (kaesar-test---unibytes-to-hex iv)))))

  ;; check interoperability openssl command
  (dolist (algorithm '("aes-128-ecb" "aes-192-ecb" "aes-256-ecb"
                       "aes-128-cbc" "aes-192-cbc" "aes-256-cbc"
                       "aes-128-ofb" "aes-192-ofb" "aes-256-ofb"
                       "aes-128-ctr" "aes-192-ctr" "aes-256-ctr"
                       "aes-128-cfb" "aes-192-cfb" "aes-256-cfb"))
    (let ((kaesar-algorithm algorithm)
          (openssl-cipher-algorithm algorithm))
      (kaesar-test---block-random-test))))

(ert-deftest kaesar-test--enc/dec ()
  :tags '(kaesar)

  ;; check accept vector
  (kaesar-test-should "abcdefg"
    (let ((kaesar-password (copy-sequence "d")))
      (kaesar-decrypt-bytes
       (let ((kaesar-password (copy-sequence "d")))
         (kaesar-encrypt-bytes (vconcat "abcdefg"))))))

  ;; less than block size
  (kaesar-test-enc/dec "abcdefghijklmno" "aes-128-ecb")
  (kaesar-test-enc/dec "abcdefghijklmno" "aes-192-ecb")
  (kaesar-test-enc/dec "abcdefghijklmno" "aes-256-ecb")
  (kaesar-test-enc/dec "abcdefghijklmno" "aes-128-cbc")
  (kaesar-test-enc/dec "abcdefghijklmno" "aes-192-cbc")
  (kaesar-test-enc/dec "abcdefghijklmno" "aes-256-cbc")

  ;; equals block size
  (kaesar-test-enc/dec "abcdefghijklmnop" "aes-128-ecb")
  (kaesar-test-enc/dec "abcdefghijklmnop" "aes-192-ecb")
  (kaesar-test-enc/dec "abcdefghijklmnop" "aes-256-ecb")
  (kaesar-test-enc/dec "abcdefghijklmnop" "aes-128-cbc")
  (kaesar-test-enc/dec "abcdefghijklmnop" "aes-192-cbc")
  (kaesar-test-enc/dec "abcdefghijklmnop" "aes-256-cbc")

  ;; exceed block size
  (kaesar-test-enc/dec "abcdefghijklmnopq" "aes-128-ecb")
  (kaesar-test-enc/dec "abcdefghijklmnopq" "aes-192-ecb")
  (kaesar-test-enc/dec "abcdefghijklmnopq" "aes-256-ecb")
  (kaesar-test-enc/dec "abcdefghijklmnopq" "aes-128-cbc")
  (kaesar-test-enc/dec "abcdefghijklmnopq" "aes-192-cbc")
  (kaesar-test-enc/dec "abcdefghijklmnopq" "aes-256-cbc"))

(ert-deftest kaesar-test--random ()
  :tags '(kaesar)

  (cl-loop repeat 256
           do
           (kaesar-test-enc/dec (kaesar-test---random-bytes) "aes-256-cbc"))

  (cl-loop repeat 256
           do
           (kaesar-test-enc/dec (kaesar-test---random-bytes) "aes-256-ecb")))

(ert-deftest kaesar-test--dec-enc-string ()
  "Increment state vector"
  :tags '(kaesar)
  (dolist (cs '(euc-jp utf-8 shift_jis))
    (let* ((text "あいうえお")
           (E (let ((kaesar-password (copy-sequence "d")))
                (kaesar-encrypt-string text cs)))
           (M (let ((kaesar-password (copy-sequence "d")))
                (kaesar-decrypt-string E cs))))
      (should (equal text M)))))


(defun kaesar-test--create-file (contents &optional cs)
  (let ((file (make-temp-file "kaesar-test-"))
        (coding-system-for-write cs))
    (write-region contents nil file nil 'no-msg)
    file))

(defun kaesar-test--file-contents (file &optional cs)
  (with-temp-buffer
    (let ((coding-system-for-read cs))
      (insert-file-contents file))
    (buffer-string)))

;;TODO check interoperability with openssl-cipher
(ert-deftest kaesar-test--file-encrypt/decrypt ()
  "Check file encryption/decryption."
  :tags '(kaesar)
  (dolist (mode '(nil base64 base64-with-header))
    (let* ((string "some of multibyte char あいうえお")
           (file (kaesar-test--create-file string)))
      (unwind-protect
          (progn
            (let ((kaesar-password (copy-sequence "d")))
              (kaesar-encrypt-file file nil mode))
            (let ((kaesar-password (copy-sequence "d")))
              ;; mode is detect automatically
              (kaesar-decrypt-file file))
            (should (equal string (kaesar-test--file-contents file)))
            ;; encrypt again. This time save file to another file.
            (let ((save-file (concat file ".save"))
                  (restore-file (concat file ".restore")))
              (unwind-protect
                  ;; FILE -> [encrypt] -> SAVE-FILE -> [decrypt] -> RESTORE-FILE
                  (progn
                    (let ((kaesar-password (copy-sequence "d")))
                      (kaesar-encrypt-file file nil mode save-file))
                    (let ((kaesar-password (copy-sequence "d")))
                      (kaesar-decrypt-file save-file nil restore-file))
                    (should (equal string (kaesar-test--file-contents restore-file))))
                (delete-file save-file)
                (delete-file restore-file))))
        (delete-file file)))))

(ert-deftest kaesar-test--region-encrypt/decrypt ()
  "Check region encryption/decryption."
  :tags '(kaesar)
  (dolist (mode '(nil base64 base64-with-header))
    (let* ((string "another multibyte string あいうえお")
           (file (kaesar-test--create-file string)))
      (let ((kaesar-password (copy-sequence "d")))
        (kaesar-encrypt-write-region string nil file nil 'utf-8 mode))
      (let ((kaesar-password (copy-sequence "d")))
        (should (equal string (kaesar-decrypt-file-contents file nil 'utf-8))))
      (with-temp-buffer
        (insert string)
        (let ((kaesar-password (copy-sequence "d")))
          (kaesar-encrypt-write-region (point-min) (point-max) file nil 'utf-8 mode)))
      (let ((kaesar-password (copy-sequence "d")))
        (should (equal string (kaesar-decrypt-file-contents file nil 'utf-8)))))))

;; TODO check decryption fail
;; TODO check cached password
;; TODO check quit when read-passwd
(ert-deftest kaesar-test--mode ()
  "Check mode encryption/decryption."
  :tags '(kaesar)
  (let* ((string "multibyte\ncharacter\nへのへの\n")
         (file (kaesar-test--create-file string 'utf-8))
         (coding-system-for-read 'utf-8))
    (unwind-protect
        (progn
          (find-file file)
          ;; using cache pass
          (let ((kaesar-mode--test-password (copy-sequence "d")))
            (kaesar-mode 1))
          (should-not (equal (kaesar-test--file-contents file 'utf-8) string))
          (kill-buffer (current-buffer))
          ;; using cache pass
          (let ((kaesar-mode--test-password (copy-sequence "d")))
            (find-file file))
          (should (equal string (buffer-string)))
          (goto-char (point-max))
          (insert "append string")
          ;; using cache pass
          (let ((kaesar-mode--test-password (copy-sequence "d")))
            (save-buffer))
          ;; decrypt and save raw data to file
          (kaesar-mode -1)
          (should (equal (kaesar-test--file-contents file 'utf-8)
                         (concat string "append string")))
          (kill-buffer (current-buffer)))
      (delete-file file))))

(ert-deftest kaesar-test--mode-file ()
  "Check mode encryption/decryption to file."
  :tags '(kaesar)
  (let* ((string "multibyte\ncharacter\nへのへの\n")
         (file (kaesar-test--create-file string 'utf-8)))
    (unwind-protect
        (progn
          (let ((kaesar-mode--test-password (copy-sequence "d")))
            (kaesar-mode-ensure-encrypt-file file))
          (should-not (equal (kaesar-test--file-contents file 'utf-8) string))
          ;; this encryption will not execute
          (should (kaesar-mode-ensure-encrypt-file file))
          (let ((kaesar-mode--test-password (copy-sequence "d")))
            (kaesar-mode-ensure-decrypt-file file))
          (should (equal (kaesar-test--file-contents file 'utf-8) string)))
      (delete-file file))))

(ert-deftest kaesar-test--change-password ()
  "Check change password."
  :tags '(kaesar)
  (let* ((M "あかさたな")
         (E (let ((kaesar-password "a"))
              (kaesar-encrypt-string M)))
         (E2 (let ((kaesar-password "a"))
               (kaesar-change-password
                E nil (lambda (old) (setq kaesar-password "b"))))))
    (should (equal (let ((kaesar-password "b"))
                     (kaesar-decrypt-string E2))
                   M))
    (should-error (let ((kaesar-password "a"))
                    (kaesar-decrypt-string E2)))))

(defconst kaesar--test-secret0001 "It's My privacy.")
(defconst kaesar--test-password0001 "c53426115d1742ae5e72")

;; (let ((kaesar-password (copy-sequence kaesar--test-password0001)))
;;   (base64-encode-string (kaesar-encrypt-string kaesar--test-secret0001))
;;   )

(ert-deftest kaesar-test--change-password ()
  "Check constants of encrypted."
  :tags '(kaesar)
  ;; This is encrypted by Emacs 28
  (dolist (encrypted '(
                       "U2FsdGVkX188Nz3PoDcWIOK/RGVQ0OEY5QAAv1Zl8Qbu7tEr7u/d0dq959kMoCWk"
                       "U2FsdGVkX19q+OmAU0ThAG6mZeI2xdCtLMlzIiiJaS84dnC9cQMYUapC1zHmhkia"
                       "U2FsdGVkX18iEOBNGao4IOtMl6tTtbfVglnB2sXBKwhPHOjrvMJ8L1y8U0ZyQbdE"
                       "U2FsdGVkX1/xS7nfItdRHUCYUT0FCS7NvOSV8yV5Z3t7AYOdvgLS1lfi0XtXI4Sa"
                       "U2FsdGVkX1/zWpHK7mOvjydnHZLrM+PCoJqviXZPnx8RwpTpcFyWCfCrsuWpM+Kt"
                       "U2FsdGVkX1+TRrAsFxO4udUb3vnujKpv/vSEiPcmU35rXCK3PjXSB/Ejk8cYyvAY"
                       "U2FsdGVkX18dZ0JHPbURm4C2S8j2umduhbfxyGa/zgGDyo1t6i0FCHZIgMrY5jdP"
                       "U2FsdGVkX19wsIFF+hI+9az17MJhRcqD1JQ0I/8TNWN+r/SZ0eCukfj28HYSIgUg"
                       "U2FsdGVkX1/2EHEKCvUkPAb4KvPDm/1N49XYtu8vgm8D4x6NgA/gHFxJPlXfVyJ7"
                       "U2FsdGVkX18qqpUft+WfhZl9pKv4VdYLj6iTGa+f0m25wSPeyqq6TUMy5nwLfyW2"
                       "U2FsdGVkX1+wMLZQ5L+h8K7A6GZ/e4N5vDmds9u4HhJhlNKH3oz4zzpG4DdmdNiM"
                       "U2FsdGVkX183BWC5a2ospYH/+u12Tsa21lIUqyvcBHBTw9+qKANI8g89DX+EhqnH"
                       ))
    (let ((kaesar-password (copy-sequence kaesar--test-password0001)))
      (should (equal kaesar--test-secret0001 (kaesar-decrypt-string (base64-decode-string encrypted)))))))

(provide 'kaesar-test)
