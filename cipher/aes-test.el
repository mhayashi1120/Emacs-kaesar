
(require 'cipher/aes)
(require 'openssl-cipher nil t)
(require 'ert)

(defun cipher/aes--test-random-bytes ()
  (let ((s (make-string (random 200) ?\000)))
    (loop for i from 0 below (length s)
          do (aset s i (random 256)))
    s))

(defun cipher/aes--test-unibytes-to-hex (unibytes)
  (apply 'concat
         (loop for b across unibytes
               collect (format "%02X" b))))

(defun cipher/aes--test-hex-to-word (hex-string)
  (unless (= (length hex-string) 8)
    (error "args out of range"))
  (cipher/aes--hex-to-vector hex-string))

(defun cipher/aes--test-openssl-key&iv (algorithm pass)
  (let ((key&iv (shell-command-to-string 
                 (format "openssl %s -e  -pass pass:%s -P -nosalt" algorithm pass))))
    (when (string-match "^key *=\\(.*\\)\\(?:\niv *=\\(.*\\)\\)?" key&iv)
      (list (match-string 1 key&iv) (or (match-string 2 key&iv) "")))))

;; Appendix A
(defun cipher/aes--test-appendix-a-result (&rest hex-strings)
  (mapcar
   (lambda (s)
     (cipher/aes--test-hex-to-word s))
   hex-strings))

(defconst cipher/aes--test-aes128-key
  [
   ?\x2b ?\x7e ?\x15 ?\x16 ?\x28 ?\xae ?\xd2 ?\xa6 ?\xab ?\xf7 ?\x15 ?\x88 ?\x09 ?\xcf ?\x4f ?\x3c
         ])

(defconst cipher/aes--test-aes128-results
  (cipher/aes--test-appendix-a-result
   "2b7e1516"
   "28aed2a6"
   "abf71588"
   "09cf4f3c"
   "a0fafe17"
   "88542cb1"
   "23a33939"
   "2a6c7605"
   "f2c295f2"
   "7a96b943"
   "5935807a"
   "7359f67f"
   "3d80477d"
   "4716fe3e"
   "1e237e44"
   "6d7a883b"
   "ef44a541"
   "a8525b7f"
   "b671253b"
   "db0bad00"
   "d4d1c6f8"
   "7c839d87"
   "caf2b8bc"
   "11f915bc"
   "6d88a37a"
   "110b3efd"
   "dbf98641"
   "ca0093fd"
   "4e54f70e"
   "5f5fc9f3"
   "84a64fb2"
   "4ea6dc4f"
   "ead27321"
   "b58dbad2"
   "312bf560"
   "7f8d292f"
   "ac7766f3"
   "19fadc21"
   "28d12941"
   "575c006e"
   "d014f9a8"
   "c9ee2589"
   "e13f0cc8"
   "b6630ca6"
   ))

(defconst cipher/aes--test-aes192-key
  [?\x8e ?\x73 ?\xb0 ?\xf7 ?\xda ?\x0e ?\x64 ?\x52 ?\xc8 ?\x10 ?\xf3 ?\x2b
         ?\x80 ?\x90 ?\x79 ?\xe5 ?\x62 ?\xf8 ?\xea ?\xd2 ?\x52 ?\x2c ?\x6b ?\x7b])

(defconst cipher/aes--test-aes192-results
  (cipher/aes--test-appendix-a-result
   "8e73b0f7"
   "da0e6452"
   "c810f32b"
   "809079e5"
   "62f8ead2"
   "522c6b7b"
   "fe0c91f7"
   "2402f5a5"
   "ec12068e"
   "6c827f6b"
   "0e7a95b9"
   "5c56fec2"
   "4db7b4bd"
   "69b54118"
   "85a74796"
   "e92538fd"
   "e75fad44"
   "bb095386"
   "485af057"
   "21efb14f"
   "a448f6d9"
   "4d6dce24"
   "aa326360"
   "113b30e6"
   "a25e7ed5"
   "83b1cf9a"
   "27f93943"
   "6a94f767"
   "c0a69407"
   "d19da4e1"
   "ec1786eb"
   "6fa64971"
   "485f7032"
   "22cb8755"
   "e26d1352"
   "33f0b7b3"
   "40beeb28"
   "2f18a259"
   "6747d26b"
   "458c553e"
   "a7e1466c"
   "9411f1df"
   "821f750a"
   "ad07d753"
   "ca400538"
   "8fcc5006"
   "282d166a"
   "bc3ce7b5"
   "e98ba06f"
   "448c773c"
   "8ecc7204"
   "01002202"
   ))

(defconst cipher/aes--test-aes256-key
  [?\x60 ?\x3d ?\xeb ?\x10 ?\x15 ?\xca ?\x71 ?\xbe ?\x2b ?\x73 ?\xae ?\xf0 ?\x85 ?\x7d ?\x77 ?\x81
         ?\x1f ?\x35 ?\x2c ?\x07 ?\x3b ?\x61 ?\x08 ?\xd7 ?\x2d ?\x98 ?\x10 ?\xa3 ?\x09 ?\x14 ?\xdf ?\xf4])

(defconst cipher/aes--test-aes256-results
  (cipher/aes--test-appendix-a-result
   "603deb10"
   "15ca71be"
   "2b73aef0"
   "857d7781"
   "1f352c07"
   "3b6108d7"
   "2d9810a3"
   "0914dff4"
   "9ba35411"
   "8e6925af"
   "a51a8b5f"
   "2067fcde"
   "a8b09c1a"
   "93d194cd"
   "be49846e"
   "b75d5b9a"
   "d59aecb8"
   "5bf3c917"
   "fee94248"
   "de8ebe96"
   "b5a9328a"
   "2678a647"
   "98312229"
   "2f6c79b3"
   "812c81ad"
   "dadf48ba"
   "24360af2"
   "fab8b464"
   "98c5bfc9"
   "bebd198e"
   "268c3ba7"
   "09e04214"
   "68007bac"
   "b2df3316"
   "96e939e4"
   "6c518d80"
   "c814e204"
   "76a9fb8a"
   "5025c02d"
   "59c58239"
   "de136967"
   "6ccc5a71"
   "fa256395"
   "9674ee15"
   "5886ca5d"
   "2e2f31d7"
   "7e0af1fa"
   "27cf73c3"
   "749c47ab"
   "18501dda"
   "e2757e4f"
   "7401905a"
   "cafaaae3"
   "e4d59b34"
   "9adf6ace"
   "bd10190d"
   "fe4890d1"
   "e6188d0b"
   "046df344"
   "706c631e"
   ))

;; Appendix B Cipher Example
(defconst cipher/aes--test-appendix-b-input-state
  [
   ?\x32 ?\x88 ?\x31 ?\xe0
   ?\x43 ?\x5a ?\x31 ?\x37
   ?\xf6 ?\x30 ?\x98 ?\x07
   ?\xa8 ?\x8d ?\xa2 ?\x34
   ])

(defconst cipher/aes--test-appendix-b-key
  [?\x2b ?\x7e ?\x15 ?\x16 ?\x28 ?\xae ?\xd2 ?\xa6 
         ?\xab ?\xf7 ?\x15 ?\x88 ?\x09 ?\xcf ?\x4f ?\x3c])

(defun cipher/aes--test-unibytes-to-state (string)
  (cipher/aes--cipher-algorithm 'aes-256
    (car (cipher/aes--parse-unibytes string 0))))

(defun cipher/aes--test-view-to-state (array)
  (let ((ret (make-vector (* cipher/aes--Row cipher/aes--Nb) nil)))
    (loop for i from 0 
          for v across array
          do (aset ret (+ (/ i cipher/aes--Nb)
                          (* (mod i cipher/aes--Row) cipher/aes--Row)) v))
    (cipher/aes--test-unibytes-to-state (concat ret))))


(defconst cipher/aes--test-appendix-b-first-round-key
  [
   ?\x2b ?\x28 ?\xab ?\x09
   ?\x7e ?\xae ?\xf7 ?\xcf
   ?\x15 ?\xd2 ?\x15 ?\x4f
   ?\x16 ?\xa6 ?\x88 ?\x3c
   ])

;; 1 Start of Round
(defconst cipher/aes--test-appendix-b-1-1
  [
   ?\x19 ?\xa0 ?\x9a ?\xe9
   ?\x3d ?\xf4 ?\xc6 ?\xf8
   ?\xe3 ?\xe2 ?\x8d ?\x48
   ?\xbe ?\x2b ?\x2a ?\x08
   ])

;; 1 After SubBytes
(defconst cipher/aes--test-appendix-b-1-2
  [
   ?\xd4 ?\xe0 ?\xb8 ?\x1e
   ?\x27 ?\xbf ?\xb4 ?\x41
   ?\x11 ?\x98 ?\x5d ?\x52
   ?\xae ?\xf1 ?\xe5 ?\x30
   ])

;; 1 After ShiftRows
(defconst cipher/aes--test-appendix-b-1-3
  [
   ?\xd4 ?\xe0 ?\xb8 ?\x1e
   ?\xbf ?\xb4 ?\x41 ?\x27
   ?\x5d ?\x52 ?\x11 ?\x98
   ?\x30 ?\xae ?\xf1 ?\xe5
   ])

;; 1 After MixColumns
(defconst cipher/aes--test-appendix-b-1-4
  [
   ?\x04 ?\xe0 ?\x48 ?\x28
   ?\x66 ?\xcb ?\xf8 ?\x06
   ?\x81 ?\x19 ?\xd3 ?\x26
   ?\xe5 ?\x9a ?\x7a ?\x4c
   ])

;; 1 Round Key Value
(defconst cipher/aes--test-appendix-b-1-round-key
  [
   ?\xa0 ?\x88 ?\x23 ?\x2a
   ?\xfa ?\x54 ?\xa3 ?\x6c
   ?\xfe ?\x2c ?\x39 ?\x76
   ?\x17 ?\xb1 ?\x39 ?\x05
   ])

;; last output
(defconst cipher/aes--test-appendix-b-last-output
  [
   ?\x39 ?\x02 ?\xdc ?\x19
   ?\x25 ?\xdc ?\x11 ?\x6a
   ?\x84 ?\x09 ?\x85 ?\x0b
   ?\x1d ?\xfb ?\x97 ?\x32
   ])

(defmacro cipher/aes-test-should (expected-form test-form)
  (declare (indent 1))
  `(should (equal ,expected-form ,test-form)))

(defun cipher/aes--test-block-random-test ()
  (flet ((read-passwd (&rest dummy) (copy-seq "d")))
    (loop repeat 16
          do (let ((bytes (cipher/aes--test-random-bytes))
                   results)
               (setq results (openssl-cipher-decrypt-unibytes (cipher/aes-encrypt bytes)))
               (cipher/aes-test-should results bytes)
               (setq results (cipher/aes-decrypt (openssl-cipher-encrypt-unibytes bytes)))
               (cipher/aes-test-should results bytes)))))

(defun cipher/aes-test-enc/dec (raw-bytes &optional algorithm)
  (flet ((read-passwd (&rest dummy) (copy-seq "d")))
    (cipher/aes-test-should raw-bytes
      (cipher/aes-decrypt (cipher/aes-encrypt raw-bytes algorithm) algorithm))))

(ert-deftest cipher/aes-test--rot ()
  :tags '(cipher/aes)
  (cipher/aes-test-should '(4 1 2 3) (cipher/aes--rot '(1 2 3 4) -1))
  (cipher/aes-test-should '(2 3 4 1) (cipher/aes--rot '(1 2 3 4) 1))
  )

(ert-deftest cipher/aes-test--basic ()
  :tags '(cipher/aes)
  ;; 4.1 Addition
  (cipher/aes-test-should ?\xd4 (cipher/aes--add ?\x57 ?\x83))

  ;; 4.2 Multiplication
  ;; section 4.2
  (cipher/aes-test-should ?\xc1 (cipher/aes--multiply ?\x57 ?\x83))

  ;; section 4.2.1
  (cipher/aes-test-should ?\xfe (cipher/aes--multiply ?\x57 ?\x13))

  )

(ert-deftest cipher/aes-test--inner-functions ()
  :tags '(cipher/aes)
  (cipher/aes--cipher-algorithm 'aes-256
    (cipher/aes-test-should [[65 70 75 80] [69 74 79 68] [73 78 67 72] [77 66 71 76]]
      (cipher/aes--shift-rows (cipher/aes--test-unibytes-to-state "ABCDEFGHIJKLMNOP")))

    (cipher/aes-test-should [[65 78 75 72] [69 66 79 76] [73 70 67 80] [77 74 71 68]] 
      (cipher/aes--inv-shift-rows (cipher/aes--test-unibytes-to-state "ABCDEFGHIJKLMNOP")))

    (cipher/aes-test-should (cipher/aes--test-unibytes-to-state "ABCDEFGHIJKLMNOP")
      (cipher/aes--inv-shift-rows (cipher/aes--shift-rows (cipher/aes--test-unibytes-to-state "ABCDEFGHIJKLMNOP"))))

    (cipher/aes-test-should (cipher/aes--test-unibytes-to-state "ABCDEFGHIJKLMNOP")
      (cipher/aes--inv-sub-bytes (cipher/aes--sub-bytes (cipher/aes--test-unibytes-to-state "ABCDEFGHIJKLMNOP"))))

    (cipher/aes-test-should (cipher/aes--test-unibytes-to-state "ABCDEFGHIJKLMNOP")
      (cipher/aes--inv-mix-columns (cipher/aes--mix-columns (cipher/aes--test-unibytes-to-state "ABCDEFGHIJKLMNOP"))))

    (cipher/aes-test-should (string-to-list "ABCDEFGHIJKLMNOP")
      (let ((key (cipher/aes--key-expansion cipher/aes--test-aes256-key)))
        (cipher/aes--state-to-bytes
         (cipher/aes--inv-cipher
          (cipher/aes--cipher (cipher/aes--test-unibytes-to-state "ABCDEFGHIJKLMNOP") key)
          key))))))

(ert-deftest cipher/aes-test--parser-functions ()
  :tags '(cipher/aes)
  
  (cipher/aes--cipher-algorithm 'aes-256
    (cipher/aes-test-should '([[97 98 99 100] [101 102 103 104] [105 106 107 108] [109 110 111 112]] 16)
      (cipher/aes--parse-unibytes "abcdefghijklmnopq" 0))

    (cipher/aes-test-should '([[97 98 99 100] [101 102 103 104] [105 106 107 108] [109 110 111 112]] 16)
      (cipher/aes--parse-unibytes "abcdefghijklmnop" 0))

    (cipher/aes-test-should '([[97 98 99 100] [101 102 103 104] [105 106 107 108] [109 110 111 1]] nil)
      (cipher/aes--parse-unibytes "abcdefghijklmno" 0))
    
    (cipher/aes-test-should '([[97 98 99 100] [101 102 103 104] [105 106 107 5] [5 5 5 5]] nil)
      (cipher/aes--parse-unibytes "abcdefghijk" 0))
    ))

(ert-deftest cipher/aes-test--openssl-compatibility ()
  :tags '(cipher/aes)

  (cipher/aes-test-should (cipher/aes--test-openssl-key&iv "aes-128-cbc" "d")
    (cipher/aes--proc "aes-128-cbc"
      (destructuring-bind (key iv) (cipher/aes--bytes-to-key (vconcat "d"))
        (list (cipher/aes--test-unibytes-to-hex key) (cipher/aes--test-unibytes-to-hex iv)))))

  (cipher/aes-test-should (cipher/aes--test-openssl-key&iv "aes-128-ecb" "d")
    (cipher/aes--proc "aes-128-ecb"
      (destructuring-bind (key iv) (cipher/aes--bytes-to-key (vconcat "d"))
        (list (cipher/aes--test-unibytes-to-hex key) (cipher/aes--test-unibytes-to-hex iv)))))

  (cipher/aes-test-should (cipher/aes--test-openssl-key&iv "aes-256-ecb" "pass")
    (cipher/aes--proc "aes-256-ecb"
      (destructuring-bind (key iv) (cipher/aes--bytes-to-key (vconcat "pass"))
        (list (cipher/aes--test-unibytes-to-hex key) (cipher/aes--test-unibytes-to-hex iv)))))

  (cipher/aes-test-should (cipher/aes--test-openssl-key&iv "aes-256-cbc" "pass")
    (cipher/aes--proc "aes-256-cbc"
      (destructuring-bind (key iv) (cipher/aes--bytes-to-key (vconcat "pass"))
        (list (cipher/aes--test-unibytes-to-hex key) (cipher/aes--test-unibytes-to-hex iv)))))

  ;; ECB
  (let ((cipher/aes-algorithm "aes-128-ecb")
        (openssl-cipher-algorithm "aes-128-ecb"))
    (cipher/aes--test-block-random-test))

  ;; CBC
  (let ((cipher/aes-algorithm "aes-128-cbc")
        (openssl-cipher-algorithm "aes-128-cbc"))
    (cipher/aes--test-block-random-test))
  )


(ert-deftest cipher/aes-test--appendix ()
  :tags '(cipher/aes)
  ;; Appendix A.1
  (cipher/aes-test-should cipher/aes--test-aes128-results
    (cipher/aes--cipher-algorithm 'aes-128 
      (cipher/aes--key-expansion cipher/aes--test-aes128-key)))

  ;; Appendix A.2
  (cipher/aes-test-should cipher/aes--test-aes192-results
    (cipher/aes--cipher-algorithm 'aes-192 
      (cipher/aes--key-expansion cipher/aes--test-aes192-key)))

  ;; Appendix A.3
  (cipher/aes-test-should cipher/aes--test-aes256-results
    (cipher/aes--cipher-algorithm 'aes-256
      (cipher/aes--key-expansion cipher/aes--test-aes256-key)))

  ;; Appendix B 
  (cipher/aes--cipher-algorithm 'aes-128
    (cipher/aes-test-should [[?\x2b ?\x7e ?\x15 ?\x16] [?\x28 ?\xae ?\xd2 ?\xa6] [?\xab ?\xf7 ?\x15 ?\x88] [?\x09 ?\xcf ?\x4f ?\x3c]]
                   (cipher/aes--round-key (cipher/aes--key-expansion cipher/aes--test-appendix-b-key) 0))

    (cipher/aes-test-should (cipher/aes--test-view-to-state cipher/aes--test-appendix-b-1-1)
                   (cipher/aes--add-round-key (cipher/aes--test-view-to-state cipher/aes--test-appendix-b-input-state) 
                                              (cipher/aes--test-view-to-state cipher/aes--test-appendix-b-first-round-key)))

    (cipher/aes-test-should (cipher/aes--test-view-to-state cipher/aes--test-appendix-b-1-2)
      (cipher/aes--sub-bytes (cipher/aes--test-view-to-state cipher/aes--test-appendix-b-1-1)))

    (cipher/aes-test-should (cipher/aes--test-view-to-state cipher/aes--test-appendix-b-1-3)
                   (cipher/aes--shift-rows (cipher/aes--test-view-to-state cipher/aes--test-appendix-b-1-2)))

    (cipher/aes-test-should (cipher/aes--test-view-to-state cipher/aes--test-appendix-b-1-4)
      (cipher/aes--mix-columns (cipher/aes--test-view-to-state cipher/aes--test-appendix-b-1-3)))

    (cipher/aes-test-should (cipher/aes--test-view-to-state cipher/aes--test-appendix-b-1-round-key)
      (cipher/aes--round-key (cipher/aes--key-expansion cipher/aes--test-appendix-b-key) (* 1 cipher/aes--Nb)))
    
    (cipher/aes-test-should (cipher/aes--test-view-to-state cipher/aes--test-appendix-b-last-output)
      (cipher/aes--cipher (cipher/aes--test-view-to-state cipher/aes--test-appendix-b-input-state)
                          (cipher/aes--key-expansion cipher/aes--test-appendix-b-key)))
    ))

(ert-deftest cipher/aes-test--enc/dec ()
  :tags '(cipher/aes)

  ;; check accept vector
  (cipher/aes-test-should "abcdefg"
    (flet ((read-passwd (&rest dummy) (copy-seq "d")))
      (cipher/aes-decrypt (cipher/aes-encrypt (vconcat "abcdefg")))))

  ;; less than block size
  (cipher/aes-test-enc/dec "abcdefghijklmno" "aes-128-ecb")
  (cipher/aes-test-enc/dec "abcdefghijklmno" "aes-192-ecb")
  (cipher/aes-test-enc/dec "abcdefghijklmno" "aes-256-ecb")
  (cipher/aes-test-enc/dec "abcdefghijklmno" "aes-128-cbc")
  (cipher/aes-test-enc/dec "abcdefghijklmno" "aes-192-cbc")
  (cipher/aes-test-enc/dec "abcdefghijklmno" "aes-256-cbc")

  ;; equals block size
  (cipher/aes-test-enc/dec "abcdefghijklmnop" "aes-128-ecb")
  (cipher/aes-test-enc/dec "abcdefghijklmnop" "aes-192-ecb")
  (cipher/aes-test-enc/dec "abcdefghijklmnop" "aes-256-ecb")
  (cipher/aes-test-enc/dec "abcdefghijklmnop" "aes-128-cbc")
  (cipher/aes-test-enc/dec "abcdefghijklmnop" "aes-192-cbc")
  (cipher/aes-test-enc/dec "abcdefghijklmnop" "aes-256-cbc")

  ;; exceed block size
  (cipher/aes-test-enc/dec "abcdefghijklmnopq" "aes-128-ecb")
  (cipher/aes-test-enc/dec "abcdefghijklmnopq" "aes-192-ecb")
  (cipher/aes-test-enc/dec "abcdefghijklmnopq" "aes-256-ecb")
  (cipher/aes-test-enc/dec "abcdefghijklmnopq" "aes-128-cbc")
  (cipher/aes-test-enc/dec "abcdefghijklmnopq" "aes-192-cbc")
  (cipher/aes-test-enc/dec "abcdefghijklmnopq" "aes-256-cbc")

  )

(ert-deftest cipher/aes-test--random ()
  :tags '(cipher/aes)

  (loop repeat 256
        do 
        (cipher/aes-test-enc/dec (cipher/aes--test-random-bytes) "aes-256-cbc"))

  (loop repeat 256
        do 
        (cipher/aes-test-enc/dec (cipher/aes--test-random-bytes) "aes-256-ecb")))

(defun cipher/aes--parse-test-values (file)
  (with-temp-buffer
    (insert-file-contents file)
    (goto-char (point-min))
    (re-search-forward "^==========$" nil t)
    (let (res)
      (while (and (not (eobp))
                  (re-search-forward "^KEYSIZE=\\([0-9]+\\)$" nil t))
        (let ((keysize (string-to-number (match-string 1)))
              (start (line-beginning-position 2))
              block data end)
          (setq end (or (and (re-search-forward "^==========$" nil t)
                             (line-beginning-position))
                        (point-max)))
          (save-restriction
            (narrow-to-region start end)
            (goto-char (point-min))
            (while (not (eobp))
              (cond
               ((looking-at "^\\([^=\n]+\\)=\\(.*\\)$")
                (let ((line (cons (match-string 1) (match-string 2))))
                  (setq block (cons line block))))
               ((looking-at "^$")
                (when block
                  (setq data (cons (nreverse block) data))
                  (setq block nil))))
              (forward-line 1))
            (setq res (cons (list keysize (nreverse data)) res)))))
      (nreverse res))))

(defun cipher/aes-test--hex-to-vector (hex)
  (loop with len = (length hex)
        with vec = (make-vector (/ len 2) nil)
        for i from 0 below len by 2
        for j from 0
        collect (let* ((s (substring hex i (+ i 2)))
                       (n (string-to-number s 16)))
                  (aset vec j n))
        finally return vec))

(defun cipher/aes-test--locate-test-data (name)
  (let ((hist (car (member-if 
                    (lambda (x) (string-match "aes-test.el" (car x)))
                    load-history))))
    (when hist
      (let* ((top (expand-file-name "../.." (car hist)))
             (datadir (expand-file-name "test/aes-test-values" top)))
        (expand-file-name name datadir)))))

(ert-deftest cipher/aes-test--variable-key ()
  "Known Answer Test (Variable Key)"
  :tags '(cipher/aes)
  (let* ((file (cipher/aes-test--locate-test-data "ecb_vk.txt"))
         (suites (cipher/aes--parse-test-values file)))
    (loop for (keysize suite) in suites
          do
          (let ((algo (format "aes-%d-ecb" keysize))
                (data (cipher/aes-test--hex-to-vector (cdr (assoc "PT" (car suite))))))
            (loop for test in (cdr suite)
                  do
                  (let* ((key (cdr (assoc "KEY" test)))
                         (ct (cdr (assoc "CT" test)))
                         (raw-key (cipher/aes-test--hex-to-vector key))
                         (enc (cipher/aes-encrypt-by-key data algo raw-key))
                         (hex (cipher/aes--test-unibytes-to-hex enc))
                         (test-target (substring hex 0 (length ct))))
                    (cipher/aes-test-should ct test-target)))))))

(ert-deftest cipher/aes-test--variable-text ()
  "Known Answer Test (Variable Text)"
  :tags '(cipher/aes)
  (let* ((file (cipher/aes-test--locate-test-data "ecb_vt.txt"))
         (suites (cipher/aes--parse-test-values file)))
    (loop for (keysize suite) in suites
          do
          (let* ((algo (format "aes-%d-ecb" keysize))
                 (key (cdr (assoc "KEY" (car suite))))
                 (raw-key (cipher/aes-test--hex-to-vector key)))
            (loop for test in (cdr suite)
                  do
                  (let* ((data (cipher/aes-test--hex-to-vector (cdr (assoc "PT" test))))
                         (ct (cdr (assoc "CT" test)))
                         (enc (cipher/aes-encrypt-by-key data algo raw-key))
                         (hex (cipher/aes--test-unibytes-to-hex enc))
                         (test-target (substring hex 0 (length ct))))
                    (cipher/aes-test-should ct test-target)))))))

(ert-deftest cipher/aes-test--tables ()
  "Known Answer Tests"
  :tags '(cipher/aes)
  (let* ((file (cipher/aes-test--locate-test-data "ecb_tbl.txt"))
         (suites (cipher/aes--parse-test-values file)))
    (loop for (keysize suite) in suites
          do
          (let* ((algo (format "aes-%d-ecb" keysize)))
            (loop for test in suite
                  do
                  (let* ((raw-key (cipher/aes-test--hex-to-vector (cdr (assoc "KEY" test))))
                         (data (cipher/aes-test--hex-to-vector (cdr (assoc "PT" test))))
                         (ct (cdr (assoc "CT" test)))
                         (enc (cipher/aes-encrypt-by-key data algo raw-key))
                         (hex (cipher/aes--test-unibytes-to-hex enc))
                         (test-target (substring hex 0 (length ct))))
                    (cipher/aes-test-should ct test-target)))))))

;; TODO ecb_iv.txt

(defun cipher/aes-test--ecb-mct (func hex-key hex-data algo)
  (let* ((raw-key (cipher/aes-test--hex-to-vector hex-key))
         (data (cipher/aes-test--hex-to-vector hex-data)))
    (cipher/aes--proc algo
      (loop with key = (cipher/aes--key-expansion raw-key)
            with state = (cipher/aes--unibytes-to-state data)
            repeat 10000
            do (setq state (funcall func state key))
            finally return (let* ((bytes (cipher/aes--state-to-bytes state))
                                  (unibytes (vconcat bytes))
                                  (hex (cipher/aes--test-unibytes-to-hex unibytes)))
                             hex)))))

;;TODO too slow
;; (ert-deftest cipher/aes-test--ecb-encrypt ()
;;   "Monte Carlo Test ECB mode decryption"
;;   :tags '(cipher/aes)
;;   (let* ((file (cipher/aes-test--locate-test-data "ecb_e_m.txt"))
;;          (suites (cipher/aes--parse-test-values file)))
;;     (loop for (keysize suite) in suites
;;           do
;;           (let* ((algo (format "aes-%d-ecb" keysize)))
;;             (loop for test in suite
;;                   do
;;                   (let* ((hex-key (cdr (assoc "KEY" test)))
;;                          (hex-data (cdr (assoc "PT" test)))
;;                          (ct (cdr (assoc "CT" test)))
;;                          (enc (cipher/aes-test--ecb-mct 'cipher/aes--cipher hex-key hex-data algo)))
;;                     (cipher/aes-test-should ct enc)))))))

;;TODO too slow
;; (ert-deftest cipher/aes-test--ecb-decrypt ()
;;   "Monte Carlo Test ECB mode decryption"
;;   :tags '(cipher/aes)
;;   (let* ((file (cipher/aes-test--locate-test-data "ecb_d_m.txt"))
;;          (suites (cipher/aes--parse-test-values file)))
;;     (loop for (keysize suite) in suites
;;           do
;;           (let* ((algo (format "aes-%d-ecb" keysize)))
;;             (loop for test in suite
;;                   do
;;                   (let* ((hex-key (cdr (assoc "KEY" test)))
;;                          (hex-data (cdr (assoc "CT" test)))
;;                          (pt (cdr (assoc "PT" test)))
;;                          (dec (cipher/aes-test--ecb-mct 'cipher/aes--inv-cipher hex-key hex-data algo)))
;;                     (cipher/aes-test-should pt dec)))))))




(provide 'cipher/aes-test)

