;;; aes.el --- Encrypt/Decrypt string with password.

;; Author: Masahiro Hayashi <mhayashi1120@gmail.com>
;; Keywords: encrypt decrypt password Rijndael
;; URL: http://github.com/mhayashi1120/Emacs-aes/raw/master/aes.el
;; Emacs: GNU Emacs 22 or later
;; Version 0.8.4

(defconst aes-version "0.8.4")

;; This program is free software; you can redistribute it and/or
;; modify it under the terms of the GNU General Public License as
;; published by the Free Software Foundation; either version 3, or (at
;; your option) any later version.

;; This program is distributed in the hope that it will be useful, but
;; WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;; General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with GNU Emacs; see the file COPYING.  If not, write to the
;; Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
;; Boston, MA 02110-1301, USA.

;;; Install:

;; Put this file into load-path'ed directory, and **BYTE COMPILE IT**. 
;; And put the following expression into your .emacs.
;;
;;     (require 'aes)

;;; Usage:

;; * To encode a well encoded string (High level API)
;; `aes-encrypt-string' <-> `aes-decrypt-string'
;;
;; * To encode a unibyte string with algorithm (Low level API)
;; `aes-encrypt' <-> `aes-decrypt'
;;
;;; Sample:

;; * To encrypt my secret
;;   Please ensure that do not forget `clear-string' you want to hide.

;; (defvar my-secret nil)

;; (let ((raw-string "My Secret"))
;;   (setq my-secret (aes-encrypt-string raw-string))
;;   (clear-string raw-string))

;; * To decrypt `my-secret'

;; (aes-decrypt-string my-secret)

;;; TODO:
;; * about algorithm
;; http://csrc.nist.gov/archive/aes/index.html
;; Rijndael algorithm

;; * cleanup temporary vector? or simply garbage-collect?

;; * refactor aes--parse-unibytes/aes--parse-encrypted

;;; Code:

(eval-when-compile
  (require 'cl))

(defcustom aes-algorithm "aes-256-cbc"
  "Cipher algorithm to encrypt a message.
Following algorithms are supported.

aes-256-ecb, aes-192-ecb, aes-128-ecb,
aes-256-cbc, aes-192-cbc, aes-128-cbc
"
  :group 'aes
  :type 'string)

(defun aes-encrypt-string (string)
  "Encrypt a well encoded STRING to encrypted object 
which can be decrypted by `aes-decrypt-string'."
  (aes-encrypt (encode-coding-string string default-terminal-coding-system)))

(defun aes-decrypt-string (encrypted-string)
  "Decrypt a ENCRYPTED-STRING which was encrypted by `aes-encrypt-string'"
  (decode-coding-string
   (aes-decrypt encrypted-string) default-terminal-coding-system))

(defun aes-encrypt (unibyte-string &optional algorithm)
  "Encrypt a UNIBYTE-STRING with ALGORITHM.
See `aes-algorithm' list the supported ALGORITHM ."
  (when (and (stringp unibyte-string)
             (multibyte-string-p unibyte-string))
    (error "Not a unibyte string"))
  (let* ((salt (aes--create-salt))
         (pass (aes--read-passwd "Password: " t)))
    (aes--proc algorithm
      (destructuring-bind (raw-key iv) (aes--bytes-to-key pass salt)
        (let ((key (aes--key-expansion raw-key)))
          (aes--create-encrypted
           (apply
            'aes--unibyte-string
            (append
             (string-to-list aes--openssl-magic-word)
             salt
             (funcall aes--Enc unibyte-string key iv)))))))))

(defun aes-decrypt (encrypted-string &optional algorithm)
  "Decrypt a ENCRYPTED-STRING which was encrypted by `aes-encrypt'"
  (when (multibyte-string-p encrypted-string)
    (error "Not a encrypted string"))
  (let ((algorithm (or algorithm (get-text-property 0 'encrypted-algorithm encrypted-string))))
    (aes--proc algorithm
      (destructuring-bind (salt encrypted-string) (aes--parse-salt encrypted-string)
        (let ((pass (aes--read-passwd "Password: ")))
          (destructuring-bind (raw-key iv) (aes--bytes-to-key pass salt)
            (let ((key (aes--key-expansion raw-key)))
              (apply 
               'aes--unibyte-string
               (funcall aes--Dec encrypted-string key iv)))))))))

(defvar aes-password nil
  "Hiding parameter hold password to suppress minibuffer prompt.")

(defun aes--read-passwd (prompt &optional confirm)
  (or (and (vectorp aes-password)
           ;; do not clear external password.
           (vconcat aes-password))
      (vconcat (read-passwd prompt confirm))))

;; Basic utilities

(defsubst aes--word-xor (word1 word2)
  (vector 
   (logxor (aref word1 0) (aref word2 0))
   (logxor (aref word1 1) (aref word2 1))
   (logxor (aref word1 2) (aref word2 2))
   (logxor (aref word1 3) (aref word2 3))))

(defsubst aes--rot (list count)
  (loop with len = (length list)
        for i from 0 below len
        collect (nth (mod (+ i count) len) list)))

(defsubst aes--byte-rot (byte count)
  (let ((v (lsh byte count)))
    (logior
     (logand ?\xff v)
     (lsh (logand ?\xff00 v) -8))))

;; Algorithm specifications

;; section 5
;; AES-128: Nk 4 Nb 4 Nr 10
;; AES-192: Nk 6 Nb 4 Nr 12
;; AES-256: Nk 8 Nb 4 Nr 14
(defconst aes--cipher-algorithm-alist
  '(
    (aes-128 4 4 10)
    (aes-192 6 4 12)
    (aes-256 8 4 14)
    ))

(defconst aes--block-algorithm-alist
  '(
    (ecb aes--ecb-encrypt aes--ecb-decrypt 0)
    (cbc aes--cbc-encrypt aes--cbc-decrypt aes--Block)
    ))

;; section 6.3
;; Block size
(defvar aes--Nb 4)

;; section 6.3
;; Key length
(defvar aes--Nk)

;; section 6.3
;; Number of rounds
(defvar aes--Nr)

(defvar aes--Enc)
(defvar aes--Dec)

;; count of row in State
(defconst aes--Row 4)
;; size of State
(defvar aes--Block)
;; size of IV (Initial Vector)
(defvar aes--IV)

(defvar aes--Algorithm)

(defun aes--parse-algorithm (name)
  (unless (string-match "^\\(aes-\\(?:128\\|192\\|256\\)\\)-\\(ecb\\|cbc\\)$" name)
    (error "%s is not supported" name))
  (list (intern (match-string 1 name)) 
        (intern (match-string 2 name))))

(defun aes--create-encrypted (string)
  (propertize string 'encrypted-algorithm aes--Algorithm))

(defmacro aes--cipher-algorithm (algorithm &rest form)
  (declare (indent 1))
  (let ((cell (make-symbol "cell")))
    `(let ((,cell (assq ,algorithm aes--cipher-algorithm-alist)))
       (unless ,cell
         (error "%s is not supported" ,algorithm))
       (let* ((aes--Nk (nth 1 ,cell))
              (aes--Nb (nth 2 ,cell))
              (aes--Nr (nth 3 ,cell))
              (aes--Block (* aes--Nb aes--Row)))
         ,@form))))

(defmacro aes--block-algorithm (algorithm &rest form)
  (declare (indent 1))
  (let ((cell (make-symbol "cell")))
    `(let ((,cell (assq ,algorithm aes--block-algorithm-alist)))
       (unless ,cell
         (error "%s is not supported" ,algorithm))
       (let* ((aes--Enc (nth 1 ,cell))
              (aes--Dec (nth 2 ,cell))
              (aes--IV (eval (nth 3 ,cell))))
         ,@form))))

(defmacro aes--proc (algorithm &rest form)
  (declare (indent 1))
  (let ((cipher (make-symbol "cipher"))
        (block-mode (make-symbol "block-mode")))
    `(let ((aes--Algorithm (or ,algorithm aes-algorithm)))
       (destructuring-bind (cipher block) (aes--parse-algorithm aes--Algorithm)
         (aes--cipher-algorithm cipher
           (aes--block-algorithm block
             ,@form))))))

;;
;; bit/number operation for Emacs
;;

(defsubst aes--unibytes-to-state (unibytes)
  (loop for r from 0 below aes--Row
        with state = (make-vector aes--Row nil)
        with len = (length unibytes)
        with suffix-len = (- aes--Block len)
        do (loop for c from 0 below aes--Nb
                 with from = (* aes--Nb r)
                 with word = (make-vector aes--Nb suffix-len)
                 initially (aset state r word)
                 while (< (+ from c) len)
                 ;; word in unibytes
                 ;; if unibytes are before encrypted, state suffixed by length
                 ;; of rest of State
                 do (aset word c (aref unibytes (+ from c))))
        finally return state))

(defsubst aes--parse-unibytes (unibyte-string pos)
  (let* ((len (length unibyte-string))
         (end-pos (min len (+ pos aes--Block)))
         (state (aes--unibytes-to-state (substring unibyte-string pos end-pos)))
         (rest (if (and (= len end-pos) 
                        (< (- end-pos pos) aes--Block))
                   nil end-pos)))
    (list state rest)))

(defsubst aes--parse-encrypted (encrypted-string)
  (let* ((len (length encrypted-string))
         (sep (min len aes--Block))
         (state (aes--unibytes-to-state (substring encrypted-string 0 sep)))
         (rest (if (= len aes--Block) nil (substring encrypted-string sep))))
    (list state rest)))

(defsubst aes--state-to-bytes (state)
  (loop for i from 0 below (* aes--Row aes--Nb)
        collect 
        (let ((r (/ i aes--Row))
              (c (% i aes--Nb)))
          (aref (aref state r) c))))

(defsubst aes--state-clone (state)
  (loop for r across state
        for i from 0
        with v = (vconcat state)
        do (aset v i (vconcat r))
        finally return v))

(defconst aes--pkcs5-salt-length 8)
(defconst aes--openssl-magic-word "Salted__")

(defun aes--create-salt ()
  (loop for i from 0 below aes--pkcs5-salt-length
        with salt = (make-vector aes--pkcs5-salt-length nil)
        do (aset salt i (random ?\x100))
        finally return salt))

(defun aes--parse-salt (unibyte-string)
  (let ((regexp (format "^%s\\([\000-\377]\\{%d\\}\\)"
                        aes--openssl-magic-word aes--pkcs5-salt-length)))
    (unless (string-match regexp unibyte-string)
      (error "No salted"))
    (list
     (vconcat (match-string 1 unibyte-string))
     (substring unibyte-string (match-end 0)))))

;; Emulate openssl EVP_BytesToKey function
;; return '(key iv)
(defun aes--bytes-to-key (data &optional salt)
  (let ((iv (make-vector aes--IV nil))
        (key (make-vector (* aes--Nk aes--Nb) nil))
        ;;md5 hash size
        (hash (make-vector 16 nil))
        (ii 0)
        (ki 0))
    (loop while (or (< ki (length key))
                    (< ii (length iv)))
          do
          (let (context)
            ;; After first loop
            (when (aref hash 0)
              (setq context (append context hash nil)))
            (setq context (append context data nil))
            (when salt
              (setq context (append context salt nil)))
            (aes--key-md5-digest hash context)
            (let ((i 0))
              (loop for j from ki below (length key)
                    while (< i (length hash))
                    do (progn 
                         (aset key j (aref hash i))
                         (incf i))
                    finally (setq ki j))
              (loop for j from ii below (length iv)
                    while (< i (length hash))
                    do (progn 
                         (aset iv j (aref hash i))
                         (incf i))
                    finally (setq ii j)))))
    (fillarray data nil)
    (list key iv)))

(defun aes--key-md5-digest (hash data)
  (loop for v across (aes--hex-to-vector (md5 (apply 'aes--unibyte-string data)))
        for i from 0
        do (aset hash i v)))

(defun aes--hex-to-vector (hex-string)
  (vconcat
   (loop for i from 0 below (length hex-string) by 2
         collect (string-to-number (substring hex-string i (+ i 2)) 16))))

(if (fboundp 'unibyte-string)
    (defalias 'aes--unibyte-string 'unibyte-string)
  (defun aes--unibyte-string (&rest bytes)
    (concat bytes)))

;;
;; AES Algorithm defined functions
;;

;; 4.1 Addition
(defsubst aes--add (&rest numbers)
  (apply 'logxor numbers))

;; 4.2 Multiplication
;; 4.2.1 xtime
(defconst aes--xtime-cache
  (loop for byte from 0 below ?\x100
        with table = (make-vector ?\x100 nil)
        do (aset table byte 
                 (if (< byte ?\x80)
                     (lsh byte 1)
                   (logand (logxor (lsh byte 1) ?\x11b) ?\xff)))
        finally return table))

(defun aes--xtime (byte)
  (aref aes--xtime-cache byte))

(defconst aes--multiply-log
  (loop for i from 0 to ?\xff
        with table = (make-vector ?\x100 nil)
        do 
        (loop for j from 1 to 7
              with l = (make-vector 8 nil)
              with v = i
              initially (progn
                          (aset table i l)
                          (aset l 0 i))
              do (let ((n (aes--xtime v)))
                   (aset l j n)
                   (setq v n)))
        finally return table))

(defun aes--multiply-0 (byte1 byte2)
  (let ((table (aref aes--multiply-log byte1)))
    (apply 'aes--add
           (loop for i from 0 to 7
                 unless (zerop (logand byte2 (lsh 1 i)))
                 collect (aref table i)))))

(defconst aes--multiply-cache 
  (vconcat
   (loop for b1 from 0 to ?\xff
         collect 
         (vconcat (loop for b2 from 0 to ?\xff
                        collect (aes--multiply-0 b1 b2))))))

(defsubst aes--multiply (byte1 byte2)
  (aref (aref aes--multiply-cache byte1) byte2))

(defconst aes--inv-multiply-cache
  (loop with v = (make-vector 256 nil)
        for byte from 0 to 255
        do (aset v byte
                 (loop for b across (aref aes--multiply-cache byte)
                       for i from 0
                       if (= b 1)
                       return i
                       finally return 0))
        finally return v))

(defsubst aes--inv-multiply (byte)
  (aref aes--inv-multiply-cache byte))

;; section 5.2
(defsubst aes--rot-word (word)
  (vector
   (aref word 1)
   (aref word 2)
   (aref word 3)
   (aref word 0)))

(defsubst aes--sub-word (word)
  (vector
   (aref aes--S-box (aref word 0))
   (aref aes--S-box (aref word 1))
   (aref aes--S-box (aref word 2))
   (aref aes--S-box (aref word 3))))

(defun aes--key-expansion (key)
  (let (res)
    (loop for i from 0 below aes--Nk
          do 
          (setq res (cons  
                     (loop for j from 0 below aes--Nb
                           with w = (make-vector aes--Nb nil)
                           do (aset w j (aref key (+ j (* aes--Nb i))))
                           finally return w)
                     res)))
    (loop for i from aes--Nk below (* aes--Nb (1+ aes--Nr))
          do (let ((temp (car res)))
               (cond
                ((= (mod i aes--Nk) 0)
                 (setq temp (aes--word-xor 
                             (aes--sub-word
                              (aes--rot-word temp))
                             ;; `i' is start from 1
                             (aref aes--Rcon (1- (/ i aes--Nk))))))
                ((and (> aes--Nk 6)
                      (= (mod i aes--Nk) 4))
                 (setq temp (aes--sub-word temp))))
               (setq res (cons
                          (aes--word-xor 
                           (nth (1- aes--Nk) res)
                           temp)
                          res))))
    (nreverse res)))

;; section 5.1.4
(defsubst aes--add-round-key (state key)
  (aset state 0 (aes--word-xor (aref state 0) (aref key 0)))
  (aset state 1 (aes--word-xor (aref state 1) (aref key 1)))
  (aset state 2 (aes--word-xor (aref state 2) (aref key 2)))
  (aset state 3 (aes--word-xor (aref state 3) (aref key 3)))
  state)

(defsubst aes--round-key (key n)
  (let ((rest (nthcdr n key)))
    (vector
     (nth 0 rest)
     (nth 1 rest)
     (nth 2 rest)
     (nth 3 rest))))

;; section 5.1.3
(defsubst aes--mix-column (word)
  (let ((w1 (vconcat word))
        (w2 (vconcat (mapcar 
                      (lambda (b)
                        (aes--multiply b 2))
                      word))))
    ;; Coefficients of word Matrix
    ;; 2 3 1 1
    ;; 1 2 3 1
    ;; 1 1 2 3
    ;; 3 1 1 2
    (aset word 0 (logxor (aref w2 0) 
                         (aref w2 1) (aref w1 1)
                         (aref w1 2) 
                         (aref w1 3)))
    (aset word 1 (logxor (aref w1 0)
                         (aref w2 1)
                         (aref w1 2) (aref w2 2)
                         (aref w1 3)))
    (aset word 2 (logxor (aref w1 0)
                         (aref w1 1) 
                         (aref w2 2)
                         (aref w1 3) (aref w2 3)))
    (aset word 3 (logxor (aref w1 0) (aref w2 0)
                         (aref w1 1)
                         (aref w1 2)
                         (aref w2 3)))))

(defsubst aes--mix-columns (state)
  (aes--mix-column (aref state 0))
  (aes--mix-column (aref state 1))
  (aes--mix-column (aref state 2))
  (aes--mix-column (aref state 3))
  state)

;; section 5.3.3
(defsubst aes--inv-mix-column (word)
  (let ((w1 (vconcat word))
        (w2 (vconcat (mapcar (lambda (b) (aes--multiply b 2)) word)))
        (w4 (vconcat (mapcar (lambda (b) (aes--multiply b 4)) word)))
        (w8 (vconcat (mapcar (lambda (b) (aes--multiply b 8)) word))))
    ;; Coefficients of word Matrix
    ;; 14 11 13  9
    ;;  9 14 11 13
    ;; 13  9 14 11
    ;; 11 13  9 14

    ;;  9 <- 8     1
    ;; 11 <- 8   2 1
    ;; 13 <- 8 4   1
    ;; 14 <- 8 4 2

    (aset word 0 (logxor 
                  (aref w8 0) (aref w4 0) (aref w2 0) ; 14
                  (aref w8 1) (aref w2 1) (aref w1 1) ; 11
                  (aref w8 2) (aref w4 2) (aref w1 2) ; 13
                  (aref w8 3) (aref w1 3)))           ;  9
    (aset word 1 (logxor 
                  (aref w8 0) (aref w1 0)               ;  9
                  (aref w8 1) (aref w4 1) (aref w2 1)   ; 14
                  (aref w8 2) (aref w2 2) (aref w1 2)   ; 11
                  (aref w8 3) (aref w4 3) (aref w1 3))) ; 13
    (aset word 2 (logxor 
                  (aref w8 0) (aref w4 0) (aref w1 0)   ; 13
                  (aref w8 1) (aref w1 1)               ;  9
                  (aref w8 2) (aref w4 2) (aref w2 2)   ; 14
                  (aref w8 3) (aref w2 3) (aref w1 3))) ; 11
    (aset word 3 (logxor
                  (aref w8 0) (aref w2 0) (aref w1 0)   ; 11
                  (aref w8 1) (aref w4 1) (aref w1 1)   ; 13
                  (aref w8 2) (aref w1 2)               ;  9
                  (aref w8 3) (aref w4 3) (aref w2 3))) ; 14
    ))

(defsubst aes--inv-mix-columns (state)
  (aes--inv-mix-column (aref state 0))
  (aes--inv-mix-column (aref state 1))
  (aes--inv-mix-column (aref state 2))
  (aes--inv-mix-column (aref state 3))
  state)

(defvar aes--Rcon
  (vconcat
   (loop repeat 10
         for v = 1 then (aes--xtime v)
         collect (vector v 0 0 0))))

;; for section 5.1.2, 5.3.1
(defsubst aes--shift-row (state row count)
  (let ((new-rows (loop for col from 0 below aes--Nb
                        collect 
                        (aref (aref state (mod (+ col count) aes--Nb)) row))))
    (loop for col from 0 below aes--Nb
          for new-row in new-rows
          do
          (aset (aref state col) row new-row))))

;; section 5.1.2
(defsubst aes--shift-rows (state)
  ;; ignore first row
  (aes--shift-row state 1 1)
  (aes--shift-row state 2 2)
  (aes--shift-row state 3 3)
  state)

;; section 5.3.1
(defsubst aes--inv-shift-rows (state)
  ;; ignore first row
  (aes--shift-row state 1 3)
  (aes--shift-row state 2 2)
  (aes--shift-row state 3 1)
  state)

;; section 5.1.1
(defun aes--s-box-0 (byte)
  (let* ((inv (aes--inv-multiply byte))
         (s inv)
         (x inv))
    (loop repeat 4
          do (progn
               (setq s (aes--byte-rot s 1))
               (setq x (logxor s x))))
    (logxor x ?\x63)))

(defconst aes--S-box
  (loop for b from 0 to ?\xff
        with box = (make-vector ?\x100 nil)
        do (aset box b (aes--s-box-0 b))
        finally return box))

(defsubst aes--sub-bytes (state)
  (loop for w across state
        do (progn 
             (aset w 0 (aref aes--S-box (aref w 0)))
             (aset w 1 (aref aes--S-box (aref w 1)))
             (aset w 2 (aref aes--S-box (aref w 2)))
             (aset w 3 (aref aes--S-box (aref w 3)))))
  state)

;; section 5.3.2
(defconst aes--inv-S-box
  (loop for s across aes--S-box
        for b from 0
        with ibox = (make-vector ?\x100 nil)
        do (aset ibox s b)
        finally return ibox))

(defsubst aes--inv-sub-bytes (state)
  (loop for w across state
        do (progn 
             (aset w 0 (aref aes--inv-S-box (aref w 0)))
             (aset w 1 (aref aes--inv-S-box (aref w 1)))
             (aset w 2 (aref aes--inv-S-box (aref w 2)))
             (aset w 3 (aref aes--inv-S-box (aref w 3)))))
  state)

;; section 5.1
(defsubst aes--cipher (state key)
  (aes--add-round-key state (aes--round-key key 0))
  (loop for round from 1 to (1- aes--Nr)
        do (progn
             (aes--sub-bytes state)
             (aes--shift-rows state)
             (aes--mix-columns state)
             (aes--add-round-key 
              state 
              (aes--round-key key (* round aes--Nb)))))
  (aes--sub-bytes state)
  (aes--shift-rows state)
  (aes--add-round-key state 
                      (aes--round-key key (* aes--Nr aes--Nb)))
  state)

;; section 5.3 
(defsubst aes--inv-cipher (state key)
  (aes--add-round-key state 
                      (aes--round-key key (* aes--Nr aes--Nb)))
  (loop for round downfrom (1- aes--Nr) to 1
        do (progn
             (aes--inv-shift-rows state)
             (aes--inv-sub-bytes state)
             (aes--add-round-key 
              state 
              (aes--round-key key (* round aes--Nb)))
             (aes--inv-mix-columns state)))
  (aes--inv-shift-rows state)
  (aes--inv-sub-bytes state)
  (aes--add-round-key state (aes--round-key key 0))
  state)

;;
;; Block mode Algorithm 
;;

(defun aes--cbc-encrypt (unibyte-string key iv)
  (loop with pos = 0
        with state-1 = (aes--unibytes-to-state iv)
        append (let* ((parsed (aes--parse-unibytes unibyte-string pos))
                      (state-d0 (aes--cbc-state-xor state-1 (nth 0 parsed)))
                      (state-e0 (aes--cipher state-d0 key)))
                 (setq pos (nth 1 parsed))
                 (setq state-1 state-e0)
                 (aes--state-to-bytes state-e0))
        while pos))

(defun aes--cbc-decrypt (encrypted-string key iv)
  (aes--check-encrypted-string encrypted-string)
  (loop with rest = encrypted-string
        with state-1 = (aes--unibytes-to-state iv)
        append (let* ((parsed (aes--parse-encrypted rest))
                      (state-e (nth 0 parsed))
                      ;; Clone state cause of `aes--inv-cipher' have side-effect
                      (state-e0 (aes--state-clone state-e))
                      (state-d0 (aes--cbc-state-xor state-1 (aes--inv-cipher state-e key)))
                      (bytes (aes--state-to-bytes state-d0)))
                 (setq rest (nth 1 parsed))
                 (setq state-1 state-e0)
                 (unless rest
                   (setq bytes (aes--check-end-of-decrypted bytes)))
                 (append bytes nil))
        while rest))

(defun aes--cbc-state-xor (state-1 state0)
  (loop for w1 across state-1
        for w2 across state0
        for i from 0
        with state = (make-vector aes--Row nil)
        do (aset state i (aes--word-xor w1 w2))
        finally return state))

;; check End-Of-Block bytes
(defun aes--check-end-of-decrypted (eob-bytes)
  (let* ((pad (car (last eob-bytes)))
         (valid-len (- aes--Block pad)))
    (when (or (> valid-len (length eob-bytes))
              (< valid-len 0))
      (error "Bad decrypt"))
    ;; check non padding byte exists
    ;; o aaa => '(97 97 97 13 13 .... 13)
    ;; x aaa => '(97 97 97 13 10 .... 13)
    (when (remove pad (nthcdr valid-len eob-bytes))
      (error "Bad decrypt"))
    (loop for i from 0 below valid-len
          for u in eob-bytes
          collect u)))

(defun aes--check-encrypted-string (string)
  (unless (= (mod (length string) aes--Block) 0)
    (error "Bad decrypt")))

(defun aes--ecb-encrypt (unibyte-string key &rest dummy)
  (loop with pos = 0
        append (let* ((parse (aes--parse-unibytes unibyte-string pos))
                      (in-state (nth 0 parse))
                      (out-state (aes--cipher in-state key)))
                 (setq pos (nth 1 parse))
                 (aes--state-to-bytes out-state))
        while pos))

(defun aes--ecb-decrypt (encrypted-string key &rest dummy)
  (aes--check-encrypted-string encrypted-string)
  (loop with rest = encrypted-string
        append (let* ((parse (aes--parse-encrypted rest))
                      (in-state (nth 0 parse))
                      (out-state (aes--inv-cipher in-state key))
                      (bytes (aes--state-to-bytes out-state)))
                 (setq rest (nth 1 parse))
                 (unless rest
                   (setq bytes (aes--check-end-of-decrypted bytes)))
                 (append bytes nil))
        while rest))

(provide 'aes)

;;; aes.el ends here
