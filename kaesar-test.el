(require 'kaesar)
(require 'kaesar-file)
(require 'kaesar-mode)
(require 'kaesar-pbkdf2)
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

(ert-deftest kaesar-test--literal-encoded ()
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

(defun delimiterize->hex (l)
  (mapconcat
   (lambda (n) (format "%02x" n))
   l " "))

(defun hex->unibytes (h)
  (cl-loop for i from 0 below (length h) by 2
           collect (string-to-number (substring h i (+ i 2)) 16)
           into bytes
           finally return (apply 'unibyte-string bytes)))

(defun kaesar-test-sha1-pbkdf2 (pass iter size salt)
  (delimiterize->hex (kaesar-pbkdf2-hmac pass iter size salt 'sha1)))

(ert-deftest kaesar-test--pbkdf2-rfc3962 ()
  "RFC 3962 (B.  Sample Test Vectors)"
  :tags '(kaesar kaesar-pbkdf2)
  (should (equal
           "cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15"
           (kaesar-test-sha1-pbkdf2 "password" 1 16  "ATHENA.MIT.EDUraeburn")))
  (should (equal
           "cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15 0a d1 f7 a0 4b b9 f3 a3 33 ec c0 e2 e1 f7 08 37"
           (kaesar-test-sha1-pbkdf2 "password" 1 32  "ATHENA.MIT.EDUraeburn")))

  (should (equal
           "01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d"
           (kaesar-test-sha1-pbkdf2 "password" 2 16  "ATHENA.MIT.EDUraeburn")))
  (should (equal
           "01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d a0 53 78 b9 32 44 ec 8f 48 a9 9e 61 ad 79 9d 86"
           (kaesar-test-sha1-pbkdf2 "password" 2 32  "ATHENA.MIT.EDUraeburn")))

  (should (equal
           "5c 08 eb 61 fd f7 1e 4e 4e c3 cf 6b a1 f5 51 2b"
           (kaesar-test-sha1-pbkdf2 "password" 1200 16  "ATHENA.MIT.EDUraeburn")))
  (should (equal
           "5c 08 eb 61 fd f7 1e 4e 4e c3 cf 6b a1 f5 51 2b a7 e5 2d db c5 e5 14 2f 70 8a 31 e2 e6 2b 1e 13"
           (kaesar-test-sha1-pbkdf2 "password" 1200 32  "ATHENA.MIT.EDUraeburn")))

  (should (equal
           "d1 da a7 86 15 f2 87 e6 a1 c8 b1 20 d7 06 2a 49"
           (kaesar-test-sha1-pbkdf2 "password" 5 16  (hex->unibytes "1234567878563412"))))
  (should (equal
           "d1 da a7 86 15 f2 87 e6 a1 c8 b1 20 d7 06 2a 49 3f 98 d2 03 e6 be 49 a6 ad f4 fa 57 4b 6e 64 ee"
           (kaesar-test-sha1-pbkdf2 "password" 5 32  (hex->unibytes "1234567878563412"))))

  (should (equal
           "13 9c 30 c0 96 6b c3 2b a5 5f db f2 12 53 0a c9"
           (kaesar-test-sha1-pbkdf2 "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
                                    1200 16  "pass phrase equals block size")))
  (should (equal
           "13 9c 30 c0 96 6b c3 2b a5 5f db f2 12 53 0a c9 c5 ec 59 f1 a4 52 f5 cc 9a d9 40 fe a0 59 8e d1"
           (kaesar-test-sha1-pbkdf2 "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
                                    1200 32  "pass phrase equals block size")))

  (should (equal
           "9c ca d6 d4 68 77 0c d5 1b 10 e6 a6 87 21 be 61"
           (kaesar-test-sha1-pbkdf2 "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
                                    1200 16 "pass phrase exceeds block size")))
  (should (equal
           "9c ca d6 d4 68 77 0c d5 1b 10 e6 a6 87 21 be 61 1a 8b 4d 28 26 01 db 3b 36 be 92 46 91 5e c8 2a"
           (kaesar-test-sha1-pbkdf2 "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
                                    1200 32 "pass phrase exceeds block size")))

  (should (equal
           "6b 9c f2 6d 45 45 5a 43 a5 b8 bb 27 6a 40 3b 39"
           (kaesar-test-sha1-pbkdf2 (hex->unibytes "f09d849e") 50 16 "EXAMPLE.COMpianist")))
  (should (equal
           "6b 9c f2 6d 45 45 5a 43 a5 b8 bb 27 6a 40 3b 39 e7 fe 37 a0 c4 1e 02 c2 81 ff 30 69 e1 e9 4f 52"
           (kaesar-test-sha1-pbkdf2 (hex->unibytes "f09d849e") 50 32 "EXAMPLE.COMpianist")))

  )

(provide 'kaesar-test)
