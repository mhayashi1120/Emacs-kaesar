
(require 'kaesar)
(require 'openssl-cipher)
(require 'ert)

(defun kaesar--test-random-bytes ()
  (let ((s (make-string (random 200) ?\000)))
    (loop for i from 0 below (length s)
          do (aset s i (random 256)))
    s))

(defun kaesar--test-unibytes-to-hex (unibytes)
  (apply 'concat
         (loop for b across unibytes
               collect (format "%02X" b))))

(defun kaesar--test-hex-to-word (hex-string)
  (unless (= (length hex-string) 8)
    (error "args out of range"))
  (kaesar--hex-to-vector hex-string))

(defun kaesar--test-openssl-key&iv (algorithm pass)
  (let ((key&iv (shell-command-to-string 
                 (format "openssl %s -e  -pass pass:%s -P -nosalt" algorithm pass))))
    (when (string-match "^key *=\\(.*\\)\\(?:\niv *=\\(.*\\)\\)?" key&iv)
      (list (match-string 1 key&iv) (or (match-string 2 key&iv) "")))))

;; Appendix A
(defun kaesar--test-appendix-a-result (&rest hex-strings)
  (mapcar
   (lambda (s)
     (kaesar--test-hex-to-word s))
   hex-strings))

(defconst kaesar--test-aes128-key
  [
   ?\x2b ?\x7e ?\x15 ?\x16 ?\x28 ?\xae ?\xd2 ?\xa6 ?\xab ?\xf7 ?\x15 ?\x88 ?\x09 ?\xcf ?\x4f ?\x3c
         ])

(defconst kaesar--test-aes128-results
  (kaesar--test-appendix-a-result
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

(defconst kaesar--test-aes192-key
  [?\x8e ?\x73 ?\xb0 ?\xf7 ?\xda ?\x0e ?\x64 ?\x52 ?\xc8 ?\x10 ?\xf3 ?\x2b
         ?\x80 ?\x90 ?\x79 ?\xe5 ?\x62 ?\xf8 ?\xea ?\xd2 ?\x52 ?\x2c ?\x6b ?\x7b])

(defconst kaesar--test-aes192-results
  (kaesar--test-appendix-a-result
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

(defconst kaesar--test-aes256-key
  [?\x60 ?\x3d ?\xeb ?\x10 ?\x15 ?\xca ?\x71 ?\xbe ?\x2b ?\x73 ?\xae ?\xf0 ?\x85 ?\x7d ?\x77 ?\x81
         ?\x1f ?\x35 ?\x2c ?\x07 ?\x3b ?\x61 ?\x08 ?\xd7 ?\x2d ?\x98 ?\x10 ?\xa3 ?\x09 ?\x14 ?\xdf ?\xf4])

(defconst kaesar--test-aes256-results
  (kaesar--test-appendix-a-result
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
(defconst kaesar--test-appendix-b-input-state
  [
   ?\x32 ?\x88 ?\x31 ?\xe0
   ?\x43 ?\x5a ?\x31 ?\x37
   ?\xf6 ?\x30 ?\x98 ?\x07
   ?\xa8 ?\x8d ?\xa2 ?\x34
   ])

(defconst kaesar--test-appendix-b-key
  [?\x2b ?\x7e ?\x15 ?\x16 ?\x28 ?\xae ?\xd2 ?\xa6 
         ?\xab ?\xf7 ?\x15 ?\x88 ?\x09 ?\xcf ?\x4f ?\x3c])

(defun kaesar--test-unibytes-to-state (string)
  (kaesar--cipher-algorithm 'aes-256
    (let ((s (kaesar--construct-state)))
      (kaesar--load-unibytes! s string 0)
      s)))

(defun kaesar--test-view-to-state (array)
  (let ((ret (make-vector (* kaesar--Row kaesar--Nb) nil)))
    (loop for i from 0 
          for v across array
          do (aset ret (+ (/ i kaesar--Nb)
                          (* (mod i kaesar--Row) kaesar--Row)) v))
    (kaesar--test-unibytes-to-state (concat ret))))


(defconst kaesar--test-appendix-b-first-round-key
  [
   ?\x2b ?\x28 ?\xab ?\x09
   ?\x7e ?\xae ?\xf7 ?\xcf
   ?\x15 ?\xd2 ?\x15 ?\x4f
   ?\x16 ?\xa6 ?\x88 ?\x3c
   ])

;; 1 Start of Round
(defconst kaesar--test-appendix-b-1-1
  [
   ?\x19 ?\xa0 ?\x9a ?\xe9
   ?\x3d ?\xf4 ?\xc6 ?\xf8
   ?\xe3 ?\xe2 ?\x8d ?\x48
   ?\xbe ?\x2b ?\x2a ?\x08
   ])

;; 1 After SubBytes
(defconst kaesar--test-appendix-b-1-2
  [
   ?\xd4 ?\xe0 ?\xb8 ?\x1e
   ?\x27 ?\xbf ?\xb4 ?\x41
   ?\x11 ?\x98 ?\x5d ?\x52
   ?\xae ?\xf1 ?\xe5 ?\x30
   ])

;; 1 After ShiftRows
(defconst kaesar--test-appendix-b-1-3
  [
   ?\xd4 ?\xe0 ?\xb8 ?\x1e
   ?\xbf ?\xb4 ?\x41 ?\x27
   ?\x5d ?\x52 ?\x11 ?\x98
   ?\x30 ?\xae ?\xf1 ?\xe5
   ])

;; 1 After MixColumns
(defconst kaesar--test-appendix-b-1-4
  [
   ?\x04 ?\xe0 ?\x48 ?\x28
   ?\x66 ?\xcb ?\xf8 ?\x06
   ?\x81 ?\x19 ?\xd3 ?\x26
   ?\xe5 ?\x9a ?\x7a ?\x4c
   ])

;; 1 Round Key Value
(defconst kaesar--test-appendix-b-1-round-key
  [
   ?\xa0 ?\x88 ?\x23 ?\x2a
   ?\xfa ?\x54 ?\xa3 ?\x6c
   ?\xfe ?\x2c ?\x39 ?\x76
   ?\x17 ?\xb1 ?\x39 ?\x05
   ])

;; last output
(defconst kaesar--test-appendix-b-last-output
  [
   ?\x39 ?\x02 ?\xdc ?\x19
   ?\x25 ?\xdc ?\x11 ?\x6a
   ?\x84 ?\x09 ?\x85 ?\x0b
   ?\x1d ?\xfb ?\x97 ?\x32
   ])

(defmacro kaesar-test-should (expected-form test-form)
  (declare (indent 1))
  `(should (equal ,expected-form ,test-form)))

(defun kaesar--test-block-random-test ()
  (let* ((bytes (kaesar--test-random-bytes))
         results)
    (let ((openssl-cipher-password (copy-seq "d"))
          (kaesar-password (copy-seq "d")))
      (setq results (openssl-cipher-decrypt-unibytes (kaesar-encrypt-bytes bytes)))
      (kaesar-test-should results bytes))

    (let ((openssl-cipher-password (copy-seq "d"))
          (kaesar-password (copy-seq "d")))
      (setq results (kaesar-decrypt-bytes (openssl-cipher-encrypt-unibytes bytes)))
      (kaesar-test-should results bytes))))

(defun kaesar-test-enc/dec (raw-bytes &optional algorithm)
  (kaesar-test-should raw-bytes
    (let ((kaesar-password (copy-seq "d")))
      (kaesar-decrypt-bytes 
       (let ((kaesar-password (copy-seq "d")))
         (kaesar-encrypt-bytes raw-bytes algorithm)) algorithm))))

(defun kaesar-test--pseudo-old-reader (string pos)
  (let* ((s (kaesar--construct-state))
         (rest (kaesar--load-unibytes! s string 0)))
    (list s rest)))

(ert-deftest kaesar-test--rot ()
  :tags '(kaesar)
  (kaesar-test-should [2 3 4 1] (kaesar--rot-word! (vconcat [1 2 3 4])))
  )

(ert-deftest kaesar-test--basic ()
  :tags '(kaesar)
  ;; 4.1 Addition
  (kaesar-test-should ?\xd4 (kaesar--add ?\x57 ?\x83))

  ;; 4.2 Multiplication
  ;; section 4.2
  (kaesar-test-should ?\xc1 (kaesar--multiply ?\x57 ?\x83))

  ;; section 4.2.1
  (kaesar-test-should ?\xfe (kaesar--multiply ?\x57 ?\x13))

  )

(ert-deftest kaesar-test--inner-functions ()
  :tags '(kaesar)
  (kaesar--cipher-algorithm 'aes-256

    ;; Sub Bytes and Shift Row with inverse
    (kaesar-test-should (kaesar--test-unibytes-to-state "ABCDEFGHIJKLMNOP")
      (kaesar--inv-sub/shift-row! (kaesar--sub/shift-row! (kaesar--test-unibytes-to-state "ABCDEFGHIJKLMNOP"))))

    (kaesar-test-should (kaesar--test-unibytes-to-state "ABCDEFGHIJKLMNOP")
      (let ((dummy-key [[0 0 0 0][0 0 0 0][0 0 0 0][0 0 0 0]]))
        (kaesar--inv-key-with-mix-columns! dummy-key (kaesar--mix-columns-with-key! (kaesar--test-unibytes-to-state "ABCDEFGHIJKLMNOP") dummy-key))))

    (kaesar-test-should (string-to-list "ABCDEFGHIJKLMNOP")
      (let ((key (kaesar--expand-to-block-key kaesar--test-aes256-key)))
        (kaesar--state-to-bytes
         (kaesar--inv-cipher!
          (kaesar--cipher! (kaesar--test-unibytes-to-state "ABCDEFGHIJKLMNOP") key)
          key))))))

(ert-deftest kaesar-test--parser-functions ()
  :tags '(kaesar)
  
  (kaesar--cipher-algorithm 'aes-256
    (kaesar-test-should '([[97 98 99 100] [101 102 103 104] [105 106 107 108] [109 110 111 112]] 16)
      (kaesar-test--pseudo-old-reader "abcdefghijklmnopq" 0))

    (kaesar-test-should '([[97 98 99 100] [101 102 103 104] [105 106 107 108] [109 110 111 112]] 16)
      (kaesar-test--pseudo-old-reader "abcdefghijklmnop" 0))

    (kaesar-test-should '([[97 98 99 100] [101 102 103 104] [105 106 107 108] [109 110 111 1]] nil)
      (kaesar-test--pseudo-old-reader "abcdefghijklmno" 0))
    
    (kaesar-test-should '([[97 98 99 100] [101 102 103 104] [105 106 107 5] [5 5 5 5]] nil)
      (kaesar-test--pseudo-old-reader "abcdefghijk" 0))
    ))

(ert-deftest kaesar-test--openssl-compatibility ()
  :tags '(kaesar)

  (kaesar-test-should (kaesar--test-openssl-key&iv "aes-128-cbc" "d")
    (kaesar--with-algorithm "aes-128-cbc"
      (destructuring-bind (key iv) (kaesar--openssl-evp-bytes-to-key (vconcat "d"))
        (list (kaesar--test-unibytes-to-hex key) (kaesar--test-unibytes-to-hex iv)))))

  (kaesar-test-should (kaesar--test-openssl-key&iv "aes-128-ecb" "d")
    (kaesar--with-algorithm "aes-128-ecb"
      (destructuring-bind (key iv) (kaesar--openssl-evp-bytes-to-key (vconcat "d"))
        (list (kaesar--test-unibytes-to-hex key) (kaesar--test-unibytes-to-hex iv)))))

  (kaesar-test-should (kaesar--test-openssl-key&iv "aes-256-ecb" "pass")
    (kaesar--with-algorithm "aes-256-ecb"
      (destructuring-bind (key iv) (kaesar--openssl-evp-bytes-to-key (vconcat "pass"))
        (list (kaesar--test-unibytes-to-hex key) (kaesar--test-unibytes-to-hex iv)))))

  (kaesar-test-should (kaesar--test-openssl-key&iv "aes-256-cbc" "pass")
    (kaesar--with-algorithm "aes-256-cbc"
      (destructuring-bind (key iv) (kaesar--openssl-evp-bytes-to-key (vconcat "pass"))
        (list (kaesar--test-unibytes-to-hex key) (kaesar--test-unibytes-to-hex iv)))))

  ;; check interoperability openssl command
  (dolist (algorithm '("aes-128-ecb" "aes-192-ecb" "aes-256-ecb"
                       "aes-128-cbc" "aes-192-cbc" "aes-256-cbc"
                       "aes-128-ofb" "aes-192-ofb" "aes-256-ofb"
                       "aes-128-ctr" "aes-192-ctr" "aes-256-ctr"
                       "aes-128-cfb" "aes-192-cfb" "aes-256-cfb"))
    (let ((kaesar-algorithm algorithm)
          (openssl-cipher-algorithm algorithm))
      (kaesar--test-block-random-test))))


(ert-deftest kaesar-test--appendix ()
  :tags '(kaesar)
  ;; Appendix A.1
  (kaesar-test-should kaesar--test-aes128-results
    (kaesar--cipher-algorithm 'aes-128 
      (kaesar--key-expansion kaesar--test-aes128-key)))

  ;; Appendix A.2
  (kaesar-test-should kaesar--test-aes192-results
    (kaesar--cipher-algorithm 'aes-192 
      (kaesar--key-expansion kaesar--test-aes192-key)))

  ;; Appendix A.3
  (kaesar-test-should kaesar--test-aes256-results
    (kaesar--cipher-algorithm 'aes-256
      (kaesar--key-expansion kaesar--test-aes256-key)))

  ;; Appendix B 
  (kaesar--cipher-algorithm 'aes-128
    (kaesar-test-should [[?\x2b ?\x7e ?\x15 ?\x16] [?\x28 ?\xae ?\xd2 ?\xa6] [?\xab ?\xf7 ?\x15 ?\x88] [?\x09 ?\xcf ?\x4f ?\x3c]]
      (kaesar--round-key (kaesar--expand-to-block-key kaesar--test-appendix-b-key) 0))

    (kaesar-test-should (kaesar--test-view-to-state kaesar--test-appendix-b-1-1)
      (kaesar--add-round-key! (kaesar--test-view-to-state kaesar--test-appendix-b-input-state) 
                              (kaesar--test-view-to-state kaesar--test-appendix-b-first-round-key)))

    (kaesar-test-should (kaesar--test-view-to-state kaesar--test-appendix-b-1-3)
      (kaesar--sub/shift-row! (kaesar--test-view-to-state kaesar--test-appendix-b-1-1)))

    ;; This case originally just test MixColumns but now is merged with AddRoundKey.
    ;; xor with key which is filled by zero get same result of original case.
    (kaesar-test-should (kaesar--test-view-to-state kaesar--test-appendix-b-1-4)
      (kaesar--mix-columns-with-key! (kaesar--test-view-to-state kaesar--test-appendix-b-1-3)
                                     [[0 0 0 0][0 0 0 0][0 0 0 0][0 0 0 0]]))
  
    (kaesar-test-should (kaesar--test-view-to-state kaesar--test-appendix-b-1-round-key)
      (kaesar--round-key (kaesar--expand-to-block-key kaesar--test-appendix-b-key) 1))
    
    (kaesar-test-should (kaesar--test-view-to-state kaesar--test-appendix-b-last-output)
      (kaesar--cipher! (kaesar--test-view-to-state kaesar--test-appendix-b-input-state)
                      (kaesar--expand-to-block-key kaesar--test-appendix-b-key)))
    ))

(ert-deftest kaesar-test--enc/dec ()
  :tags '(kaesar)

  ;; check accept vector
  (kaesar-test-should "abcdefg"
    (let ((kaesar-password (copy-seq "d")))
      (kaesar-decrypt-bytes
       (let ((kaesar-password (copy-seq "d")))
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

  (loop repeat 256
        do 
        (kaesar-test-enc/dec (kaesar--test-random-bytes) "aes-256-cbc"))

  (loop repeat 256
        do 
        (kaesar-test-enc/dec (kaesar--test-random-bytes) "aes-256-ecb")))

(defun kaesar--parse-test-values (file)
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
          (setq end (or (and (re-search-forward "^=+$" nil t)
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

(defun kaesar-test--hex-to-unibyte (hex)
  (apply 'unibyte-string
         (append (kaesar-test--hex-to-vector hex) nil)))

(defun kaesar-test--hex-to-vector (hex)
  (loop with len = (length hex)
        with vec = (make-vector (/ len 2) nil)
        for i from 0 below len by 2
        for j from 0
        collect (let* ((s (substring hex i (+ i 2)))
                       (n (string-to-number s 16)))
                  (aset vec j n))
        finally return vec))

(defun kaesar-test--locate-test-data (name)
  (let ((hist (car (member-if 
                    (lambda (x) (string-match "kaesar-test.el" (car x)))
                    load-history))))
    (when hist
      (let* ((top (expand-file-name ".." (car hist)))
             (datadir (expand-file-name "test/aes-test-values" top)))
        (expand-file-name name datadir)))))

(ert-deftest kaesar-test--variable-key ()
  "Known Answer Test (Variable Key)"
  :tags '(kaesar)
  (let* ((file (kaesar-test--locate-test-data "ecb_vk.txt"))
         (suites (kaesar--parse-test-values file)))
    (loop for (keysize suite) in suites
          do
          (let ((algo (format "aes-%d-ecb" keysize))
                (data (kaesar-test--hex-to-vector (cdr (assoc "PT" (car suite))))))
            (loop for test in (cdr suite)
                  do
                  (let* ((key (cdr (assoc "KEY" test)))
                         (ct (cdr (assoc "CT" test)))
                         (raw-key (kaesar-test--hex-to-vector key))
                         (enc (kaesar-encrypt data raw-key nil algo))
                         (hex (kaesar--test-unibytes-to-hex enc))
                         (test-target (substring hex 0 (length ct))))
                    (kaesar-test-should ct test-target)))))))

(ert-deftest kaesar-test--variable-text ()
  "Known Answer Test (Variable Text)"
  :tags '(kaesar)
  (let* ((file (kaesar-test--locate-test-data "ecb_vt.txt"))
         (suites (kaesar--parse-test-values file)))
    (loop for (keysize suite) in suites
          do
          (let* ((algo (format "aes-%d-ecb" keysize))
                 (key (cdr (assoc "KEY" (car suite))))
                 (raw-key (kaesar-test--hex-to-vector key)))
            (loop for test in (cdr suite)
                  do
                  (let* ((data (kaesar-test--hex-to-vector (cdr (assoc "PT" test))))
                         (ct (cdr (assoc "CT" test)))
                         (enc (kaesar-encrypt data raw-key nil algo))
                         (hex (kaesar--test-unibytes-to-hex enc))
                         (test-target (substring hex 0 (length ct))))
                    (kaesar-test-should ct test-target)))))))

(ert-deftest kaesar-test--tables ()
  "Known Answer Tests"
  :tags '(kaesar)
  (let* ((file (kaesar-test--locate-test-data "ecb_tbl.txt"))
         (suites (kaesar--parse-test-values file)))
    (loop for (keysize suite) in suites
          do
          (let* ((algo (format "aes-%d-ecb" keysize)))
            (loop for test in suite
                  do
                  (let* ((raw-key (kaesar-test--hex-to-vector (cdr (assoc "KEY" test))))
                         (data (kaesar-test--hex-to-vector (cdr (assoc "PT" test))))
                         (ct (cdr (assoc "CT" test)))
                         (enc (kaesar-encrypt data raw-key nil algo))
                         (hex (kaesar--test-unibytes-to-hex enc))
                         (test-target (substring hex 0 (length ct))))
                    (kaesar-test-should ct test-target)))))))


(ert-deftest kaesar-test--ctr-mode ()
  "Increment state vector"
  :tags '(kaesar)
  (let ((s 
         (vector
          (vector 255 255 255 255)
          (vector 255 255 255 255)
          (vector 255 255 255 255)
          (vector 255 255 255 254))))
    (kaesar--ctr-increment! s)
    (should (equal [[255 255 255 255] [255 255 255 255] [255 255 255 255] [255 255 255 255]] s))
    (kaesar--ctr-increment! s)
    (should (equal [[0 0 0 0] [0 0 0 0] [0 0 0 0] [0 0 0 0]] s))
    (kaesar--ctr-increment! s)
    (should (equal [[0 0 0 0] [0 0 0 0] [0 0 0 0] [0 0 0 1]] s))
    s))

(ert-deftest kaesar-test--checking-unibyte-vector ()
  "Increment state vector"
  :tags '(kaesar)
  (should (equal (kaesar--check-unibyte-vector [0 255]) [0 255]))
  (should (kaesar--check-unibyte-vector "a"))
  (should-error (kaesar--check-unibyte-vector [-1]))
  (should-error (kaesar--check-unibyte-vector [256]))
  (should-error (kaesar--check-unibyte-vector [a]))
  (should-error (kaesar--check-unibyte-vector (decode-coding-string "\343\201\202" 'utf-8)))
  (kaesar--with-algorithm "aes-128-cbc"
    (should (equal (vconcat (make-vector 15 0) [1]) (kaesar--validate-key "1")))
    (should (equal (vconcat (make-vector 15 0) [1]) (kaesar--validate-key "01")))
    (should (equal (vconcat (make-vector 15 0) [170]) (kaesar--validate-key "aa")))
    (should (equal (make-vector 16 170) (kaesar--validate-key "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")))
    (should (equal (make-vector 16 170) (kaesar--validate-key "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")))
    (should (equal (make-vector 16 ?a) (kaesar--validate-key "aaaaaaaaaaaaaaaa")))
    (should (equal (make-vector 16 ?b) (kaesar--validate-key (make-vector 16 ?b))))))

(ert-deftest kaesar-test--dec-enc-string ()
  "Increment state vector"
  :tags '(kaesar)
  (dolist (cs '(euc-jp utf-8 shift_jis))
    (let* ((text (decode-coding-string "あいうえお" cs))
           (E (let ((kaesar-password (copy-seq "d")))
                (kaesar-encrypt-string text cs)))
           (M (let ((kaesar-password (copy-seq "d")))
                (kaesar-decrypt-string E cs))))
      (should (equal text M)))))

;; TODO ecb_iv.txt

(defun kaesar-test--ecb-mct (func hex-key hex-data algo)
  (princ (format "Checking ECB MCT ALGORITHM: %s KEY: %s DATA: %s\n" algo hex-key hex-data))
  (let* ((raw-key (kaesar-test--hex-to-vector hex-key))
         (data (kaesar-test--hex-to-unibyte hex-data)))
    (kaesar--with-algorithm algo
      (loop with key = (kaesar--expand-to-block-key raw-key)
            with state = (kaesar--unibytes-to-state data 0)
            repeat 10000
            do (setq state (funcall func state key))
            finally return (let* ((bytes (kaesar--state-to-bytes state))
                                  (unibytes (vconcat bytes))
                                  (hex (kaesar--test-unibytes-to-hex unibytes)))
                             hex)))))

(ert-deftest kaesar-test--ecb-encrypt ()
  "Monte Carlo Test ECB mode decryption"
  :tags '(kaesar)
  (loop with file = (kaesar-test--locate-test-data "ecb_e_m.txt")
        with suites = (kaesar--parse-test-values file)
        for (keysize suite) in suites
        do
        (catch 'exit
          (loop with start = (float-time)
                with algo = (format "aes-%d-ecb" keysize)
                for test in suite
                do
                (let* ((hex-key (cdr (assoc "KEY" test)))
                       (hex-data (cdr (assoc "PT" test)))
                       (ct (cdr (assoc "CT" test)))
                       (enc (kaesar-test--ecb-mct 'kaesar--cipher! hex-key hex-data algo)))
                  (kaesar-test-should ct enc)
                  ;; TODO All of test spent too many seconds
                  (when (< (+ start 10) (float-time))
                    (throw 'exit t)))))))

(ert-deftest kaesar-test--ecb-decrypt ()
  "Monte Carlo Test ECB mode decryption"
  :tags '(kaesar)
  (loop with file = (kaesar-test--locate-test-data "ecb_d_m.txt")
        with suites = (kaesar--parse-test-values file)
        for (keysize suite) in suites
        do
        (catch 'exit
          (loop with algo = (format "aes-%d-ecb" keysize)
                with start = (float-time)
                for test in suite
                do
                (let* ((hex-key (cdr (assoc "KEY" test)))
                       (hex-data (cdr (assoc "CT" test)))
                       (pt (cdr (assoc "PT" test)))
                       (dec (kaesar-test--ecb-mct 'kaesar--inv-cipher! hex-key hex-data algo)))
                  (kaesar-test-should pt dec)
                  ;; TODO All of test spent too many seconds
                  (when (< (+ start 10) (float-time))
                    (throw 'exit t)))))))


(defun kaesar-test--cbc-mct (hex-key hex-pt hex-iv algo)
  (princ (format "Checking CBC MCT ALGORITHM: %s KEY: %s IV %s DATA: %s\n"
                 algo hex-key hex-iv hex-pt))
  (let* ((raw-key (kaesar-test--hex-to-vector hex-key))
         (pt (kaesar-test--hex-to-unibyte hex-pt))
         (iv (kaesar-test--hex-to-unibyte hex-iv))
         (cv iv))
    (kaesar--with-algorithm algo
      (loop with key = (kaesar--expand-to-block-key raw-key)
            with cv = (kaesar--unibytes-to-state cv 0)
            with pt = (kaesar--unibytes-to-state pt 0)
            with ct-1 = nil
            with ct = nil
            repeat 10000
            do (let* ((_ (kaesar--state-xor! pt cv)))
                 (setq ct (kaesar--cipher! pt key))
                 (if (null ct-1)
                     (setq pt cv)
                   (setq pt ct-1))
                 (setq cv ct)
                 (setq ct-1 ct))
            finally return
            (list (kaesar--test-state-to-hex ct)
                  (kaesar--test-state-to-hex pt))))))

(defun kaesar--test-state-to-hex (state)
  (let* ((bytes (kaesar--state-to-bytes state))
         (unibytes (vconcat bytes))
         (hex (kaesar--test-unibytes-to-hex unibytes)))
    hex))

(ert-deftest kaesar-test--cbc-encrypt ()
  "Monte Carlo Test CBC mode encryption"
  :tags '(kaesar)
  (loop with file = (kaesar-test--locate-test-data "cbc_e_m.txt")
        with suites = (kaesar--parse-test-values file)
        for (keysize suite) in suites
        do
        (catch 'exit
          (loop with algo = (format "aes-%d-cbc" keysize)
                with start = (float-time)
                with prev-pt
                for test in suite
                do
                (let* ((hex-key (cdr (assoc "KEY" test)))
                       (hex-iv (cdr (assoc "IV" test)))
                       (hex-pt (cdr (assoc "PT" test)))
                       (hex-ct (cdr (assoc "CT" test))))
                  (when prev-pt
                    (kaesar-test-should hex-pt prev-pt))
                  (destructuring-bind (res-ct res-pt)
                      (kaesar-test--cbc-mct hex-key hex-pt hex-iv algo)
                    (kaesar-test-should hex-ct res-ct)
                    (setq prev-pt res-pt))
                  ;; TODO All of test spent too many seconds
                  (when (< (+ start 10) (float-time))
                    (throw 'exit t)))))))

;;TODO too slow not yet implement
;; (ert-deftest kaesar-test--ecb-decrypt ()
;;   "Monte Carlo Test CBC mode decryption"
;;   :tags '(kaesar)
;;   (let* ((file (kaesar-test--locate-test-data "cbc_d_m.txt"))
;;          (suites (kaesar--parse-test-values file)))
;;     (loop for (keysize suite) in suites
;;           do
;;           (let* ((algo (format "aes-%d-ecb" keysize)))
;;             (loop for test in suite
;;                   do
;;                   (let* ((hex-key (cdr (assoc "KEY" test)))
;;                          (hex-data (cdr (assoc "CT" test)))
;;                          (pt (cdr (assoc "PT" test)))
;;                          (dec (kaesar-test--ecb-mct 'kaesar--inv-cipher hex-key hex-data algo)))
;;                     (kaesar-test-should pt dec)))))))


(provide 'kaesar-test)

