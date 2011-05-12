
(require 'el-expectations)
(require 'aes)
(require 'openssl-cipher nil t)

(defun aes--test-dump-state (state)
  (mapc
   (lambda (col)
     (insert (mapconcat (lambda (v) (format "?\\x%02X" v)) col " ") "\n"))
   (loop for row from 0 below aes--state-Row
         collect
         (loop for col from 0 below aes--Nb
               collect (aref (aref state col) row)))))

(defun aes--test-random-bytes ()
  (let ((s (make-string (random 200) ?\000)))
    (loop for i from 0 below (length s)
          do (aset s i (random 256)))
    s))

(defun aes--test-random-string ()
  (let ((s (make-string (random 200) ?\000)))
    (loop for i from 0 below (length s)
          do (aset s i (loop with c = nil
                             do (setq c (random 65535))
                             while (not (decode-char 'ucs c))
                             finally return c)))
    s))

(defun aes--test-dump-word (word)
  (format "%02X%02X%02X%02X" 
          (nth 0 word)
          (nth 1 word)
          (nth 2 word)
          (nth 3 word)))

(defun aes--test-dump-words (words)
  (loop for word on words by (lambda (x) (nthcdr 4 x))
        collect (aes--test-dump-word word)))

(defun aes--test-dump-expanded-key (key)
  (loop for pair on key by (lambda (x) (nthcdr 4 x))
        for i from 0
        do (insert (format "%02d: %02X%02X%02X%02X\n" 
                           i
                           (nth 0 pair)
                           (nth 1 pair)
                           (nth 2 pair)
                           (nth 3 pair)))))

(defun aes--test-unibytes-to-hex (unibytes)
  (apply 'concat
         (loop for b across unibytes
               collect (format "%02X" b))))

(defun aes--test-hex-to-word (hex-string)
  (unless (= (length hex-string) 8)
    (error "args out of range"))
  (aes--hex-to-vector hex-string))

(defun aes--test-hex-to-words (hex-string)
  (unless (= (mod (length hex-string) 8) 0)
    (error "args out of range"))
  (vconcat
   (loop for i from 0 below (length hex-string) by 8
         collect (aes--test-hex-to-word (substring hex-string i (+ i 8))))))

(defun aes--test-openssl-key&iv (algorithm pass)
  (let ((key&iv (shell-command-to-string 
                 (format "openssl %s -e  -pass pass:%s -P -nosalt" algorithm pass))))
    (when (string-match "^key *=\\(.*\\)\\(?:\niv *=\\(.*\\)\\)?" key&iv)
      (list (match-string 1 key&iv) (or (match-string 2 key&iv) "")))))

;; Appendix A
(defun aes--test-appendix-a-result (&rest hex-strings)
  (mapcar
   (lambda (s)
     (aes--test-hex-to-word s))
   hex-strings))

(defconst aes--test-aes128-key
  [
   ?\x2b ?\x7e ?\x15 ?\x16 ?\x28 ?\xae ?\xd2 ?\xa6 ?\xab ?\xf7 ?\x15 ?\x88 ?\x09 ?\xcf ?\x4f ?\x3c
         ])

(defconst aes--test-aes128-results
  (aes--test-appendix-a-result
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

(defconst aes--test-aes192-key
  [?\x8e ?\x73 ?\xb0 ?\xf7 ?\xda ?\x0e ?\x64 ?\x52 ?\xc8 ?\x10 ?\xf3 ?\x2b
         ?\x80 ?\x90 ?\x79 ?\xe5 ?\x62 ?\xf8 ?\xea ?\xd2 ?\x52 ?\x2c ?\x6b ?\x7b])

(defconst aes--test-aes192-results
  (aes--test-appendix-a-result
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

(defconst aes--test-aes256-key
  [?\x60 ?\x3d ?\xeb ?\x10 ?\x15 ?\xca ?\x71 ?\xbe ?\x2b ?\x73 ?\xae ?\xf0 ?\x85 ?\x7d ?\x77 ?\x81
         ?\x1f ?\x35 ?\x2c ?\x07 ?\x3b ?\x61 ?\x08 ?\xd7 ?\x2d ?\x98 ?\x10 ?\xa3 ?\x09 ?\x14 ?\xdf ?\xf4])

(defconst aes--test-aes256-results
  (aes--test-appendix-a-result
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
(defconst aes--test-appendix-b-input-state
  [
   ?\x32 ?\x88 ?\x31 ?\xe0
   ?\x43 ?\x5a ?\x31 ?\x37
   ?\xf6 ?\x30 ?\x98 ?\x07
   ?\xa8 ?\x8d ?\xa2 ?\x34
   ])

(defconst aes--test-appendix-b-key
  [?\x2b ?\x7e ?\x15 ?\x16 ?\x28 ?\xae ?\xd2 ?\xa6 
         ?\xab ?\xf7 ?\x15 ?\x88 ?\x09 ?\xcf ?\x4f ?\x3c])

(defun aes--test-unibytes-to-state (string)
  (aes--cipher-algorithm 'aes-256
    (car (aes--parse-unibytes string))))

(defun aes--test-view-to-state (array)
  (let ((ret (make-vector (* aes--state-Row aes--Nb) nil)))
    (loop for i from 0 
          for v across array
          do (aset ret (+ (/ i aes--Nb)
                          (* (mod i aes--state-Row) aes--state-Row)) v))
    (aes--test-unibytes-to-state (concat ret))))


(defconst aes--test-appendix-b-first-round-key
  [
   ?\x2b ?\x28 ?\xab ?\x09
   ?\x7e ?\xae ?\xf7 ?\xcf
   ?\x15 ?\xd2 ?\x15 ?\x4f
   ?\x16 ?\xa6 ?\x88 ?\x3c
   ])

;; 1 Start of Round
(defconst aes--test-appendix-b-1-1
  [
   ?\x19 ?\xa0 ?\x9a ?\xe9
   ?\x3d ?\xf4 ?\xc6 ?\xf8
   ?\xe3 ?\xe2 ?\x8d ?\x48
   ?\xbe ?\x2b ?\x2a ?\x08
   ])

;; 1 After SubBytes
(defconst aes--test-appendix-b-1-2
  [
   ?\xd4 ?\xe0 ?\xb8 ?\x1e
   ?\x27 ?\xbf ?\xb4 ?\x41
   ?\x11 ?\x98 ?\x5d ?\x52
   ?\xae ?\xf1 ?\xe5 ?\x30
   ])

;; 1 After ShiftRows
(defconst aes--test-appendix-b-1-3
  [
   ?\xd4 ?\xe0 ?\xb8 ?\x1e
   ?\xbf ?\xb4 ?\x41 ?\x27
   ?\x5d ?\x52 ?\x11 ?\x98
   ?\x30 ?\xae ?\xf1 ?\xe5
   ])

;; 1 After MixColumns
(defconst aes--test-appendix-b-1-4
  [
   ?\x04 ?\xe0 ?\x48 ?\x28
   ?\x66 ?\xcb ?\xf8 ?\x06
   ?\x81 ?\x19 ?\xd3 ?\x26
   ?\xe5 ?\x9a ?\x7a ?\x4c
   ])

;; 1 Round Key Value
(defconst aes--test-appendix-b-1-round-key
  [
   ?\xa0 ?\x88 ?\x23 ?\x2a
   ?\xfa ?\x54 ?\xa3 ?\x6c
   ?\xfe ?\x2c ?\x39 ?\x76
   ?\x17 ?\xb1 ?\x39 ?\x05
   ])

;; last output
(defconst aes--test-appendix-b-last-output
  [
   ?\x39 ?\x02 ?\xdc ?\x19
   ?\x25 ?\xdc ?\x11 ?\x6a
   ?\x84 ?\x09 ?\x85 ?\x0b
   ?\x1d ?\xfb ?\x97 ?\x32
   ])

(defun aes--test-block-random-test ()
  (flet ((read-passwd (&rest dummy) (copy-seq "d")))
    (loop repeat 16
          do (let ((bytes (aes--test-random-bytes))
                   results)
               (setq results (openssl-cipher-decrypt-unibytes (aes-encrypt-unibytes bytes)))
               (unless (equal bytes results)
                 (error "Expect elisp -> openssl `%s' but `%s'" bytes results))
               (setq results (aes-decrypt-unibytes (openssl-cipher-encrypt-unibytes bytes)))
               (unless (equal bytes results)
                 (error "Expect openssl -> elisp `%s' but `%s'" bytes results))))))

(expectations
  (expect '(4 1 2 3) (aes--rot '(1 2 3 4) -1))
  (expect '(2 3 4 1) (aes--rot '(1 2 3 4) 1))

  ;; 4.1 Addition
  (expect ?\xd4 (aes--add ?\x57 ?\x83))

  ;; 4.2 Multiplication
  ;; section 4.2
  (expect ?\xc1 (aes--multiply ?\x57 ?\x83))

  ;; section 4.2.1
  (expect ?\xfe (aes--multiply ?\x57 ?\x13))

  (expect [[65 70 75 80] [69 74 79 68] [73 78 67 72] [77 66 71 76]]
    (aes--cipher-algorithm 'aes-256
      (aes--shift-rows (aes--test-unibytes-to-state "ABCDEFGHIJKLMNOP"))))

  (expect [[65 78 75 72] [69 66 79 76] [73 70 67 80] [77 74 71 68]] 
    (aes--cipher-algorithm 'aes-256
      (aes--inv-shift-rows (aes--test-unibytes-to-state "ABCDEFGHIJKLMNOP"))))

  (expect (aes--test-unibytes-to-state "ABCDEFGHIJKLMNOP")
    (aes--cipher-algorithm 'aes-256
      (aes--inv-shift-rows (aes--shift-rows (aes--test-unibytes-to-state "ABCDEFGHIJKLMNOP")))))

  (expect (aes--test-unibytes-to-state "ABCDEFGHIJKLMNOP")
    (aes--cipher-algorithm 'aes-256
      (aes--inv-sub-bytes (aes--sub-bytes (aes--test-unibytes-to-state "ABCDEFGHIJKLMNOP")))))

  (expect (aes--test-unibytes-to-state "ABCDEFGHIJKLMNOP")
    (aes--cipher-algorithm 'aes-256
      (aes--inv-mix-columns (aes--mix-columns (aes--test-unibytes-to-state "ABCDEFGHIJKLMNOP")))))

  (expect (string-to-list "ABCDEFGHIJKLMNOP")
    (aes--cipher-algorithm 'aes-256
      (let ((key (aes--key-expansion aes--test-aes256-key)))
        (aes--state-to-bytes
         (aes--inv-cipher
          (aes--cipher (aes--test-unibytes-to-state "ABCDEFGHIJKLMNOP") key)
          key)))))

  (expect '([[97 98 99 100] [101 102 103 104] [105 106 107 108] [109 110 111 112]] "q")
    (aes--cipher-algorithm 'aes-256
      (aes--parse-unibytes "abcdefghijklmnopq")))

  (expect '([[97 98 99 100] [101 102 103 104] [105 106 107 108] [109 110 111 112]] "")
    (aes--cipher-algorithm 'aes-256
      (aes--parse-unibytes "abcdefghijklmnop")))

  (expect '([[97 98 99 100] [101 102 103 104] [105 106 107 108] [109 110 111 1]] nil)
    (aes--cipher-algorithm 'aes-256
      (aes--parse-unibytes "abcdefghijklmno")))

  (expect '([[97 98 99 100] [101 102 103 104] [105 106 107 5] [5 5 5 5]] nil)
    (aes--cipher-algorithm 'aes-256
      (aes--parse-unibytes "abcdefghijk")))

  (expect (aes--test-openssl-key&iv "aes-128-cbc" "d")
    (aes--proc "aes-128-cbc"
      (destructuring-bind (key iv) (aes--bytes-to-key (string-to-vector "d"))
        (list (aes--test-unibytes-to-hex key) (aes--test-unibytes-to-hex iv)))))

  (expect (aes--test-openssl-key&iv "aes-128-ecb" "d")
    (aes--proc "aes-128-ecb"
      (destructuring-bind (key iv) (aes--bytes-to-key (string-to-vector "d"))
        (list (aes--test-unibytes-to-hex key) (aes--test-unibytes-to-hex iv)))))

  (expect (aes--test-openssl-key&iv "aes-256-ecb" "pass")
    (aes--proc "aes-256-ecb"
      (destructuring-bind (key iv) (aes--bytes-to-key (string-to-vector "pass"))
        (list (aes--test-unibytes-to-hex key) (aes--test-unibytes-to-hex iv)))))

  (expect (aes--test-openssl-key&iv "aes-256-cbc" "pass")
    (aes--proc "aes-256-cbc"
      (destructuring-bind (key iv) (aes--bytes-to-key (string-to-vector "pass"))
        (list (aes--test-unibytes-to-hex key) (aes--test-unibytes-to-hex iv)))))

  ;; Appendix A.1
  (expect aes--test-aes128-results
    (aes--cipher-algorithm 'aes-128 
      (aes--key-expansion aes--test-aes128-key)))

  ;; Appendix A.2
  (expect aes--test-aes192-results
    (aes--cipher-algorithm 'aes-192 
      (aes--key-expansion aes--test-aes192-key)))

  ;; Appendix A.3
  (expect aes--test-aes256-results
    (aes--cipher-algorithm 'aes-256
      (aes--key-expansion aes--test-aes256-key)))

  ;; Appendix B 
  (expect [[?\x2b ?\x7e ?\x15 ?\x16] [?\x28 ?\xae ?\xd2 ?\xa6] [?\xab ?\xf7 ?\x15 ?\x88] [?\x09 ?\xcf ?\x4f ?\x3c]]
    (aes--cipher-algorithm 'aes-128
      (aes--round-key (aes--key-expansion aes--test-appendix-b-key) 0)))

  (expect (aes--test-view-to-state aes--test-appendix-b-1-1)
    (aes--cipher-algorithm 'aes-128
      (aes--add-round-key (aes--test-view-to-state aes--test-appendix-b-input-state) 
                          (aes--test-view-to-state aes--test-appendix-b-first-round-key))))

  (expect (aes--test-view-to-state aes--test-appendix-b-1-2)
    (aes--cipher-algorithm 'aes-128
      (aes--sub-bytes (aes--test-view-to-state aes--test-appendix-b-1-1))))

  (expect (aes--test-view-to-state aes--test-appendix-b-1-3)
    (aes--cipher-algorithm 'aes-128
      (aes--shift-rows (aes--test-view-to-state aes--test-appendix-b-1-2))))

  (expect (aes--test-view-to-state aes--test-appendix-b-1-4)
    (aes--cipher-algorithm 'aes-128
      (aes--mix-columns (aes--test-view-to-state aes--test-appendix-b-1-3))))

  (expect (aes--test-view-to-state aes--test-appendix-b-1-round-key)
    (aes--cipher-algorithm 'aes-128
      (aes--round-key (aes--key-expansion aes--test-appendix-b-key) (* 1 aes--Nb))))

  (expect (aes--test-view-to-state aes--test-appendix-b-last-output)
    (aes--cipher-algorithm 'aes-128
      (aes--cipher (aes--test-view-to-state aes--test-appendix-b-input-state)
                   (aes--key-expansion aes--test-appendix-b-key))))

  ;; Random test
  (expect nil
    (let ((aes-algorithm "aes-256-cbc"))
      (loop repeat 256
            do 
            (flet ((read-passwd (&rest dummy) (copy-seq "d")))
              (aes-decrypt-unibytes (aes-encrypt-unibytes (aes--test-random-bytes)))))))

  (expect nil
    (let ((aes-algorithm "aes-256-ecb"))
      (loop repeat 256
            do 
            (flet ((read-passwd (&rest dummy) (copy-seq "d")))
              (aes-decrypt-unibytes (aes-encrypt-unibytes (aes--test-random-bytes)))))))

  ;; Test with openssl command

  ;; ECB
  (expect nil
    (let ((aes-algorithm "aes-128-ecb")
          (openssl-cipher-algorithm "aes-128-ecb"))
      (aes--test-block-random-test)))

  ;; CBC
  (expect nil
    (let ((aes-algorithm "aes-128-cbc")
          (openssl-cipher-algorithm "aes-128-cbc"))
      (aes--test-block-random-test)))
  )

(expectations-execute)

(provide 'aes-test)
