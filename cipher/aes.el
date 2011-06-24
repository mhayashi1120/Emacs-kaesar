;;; cipher/aes.el --- Encrypt/Decrypt string with password.

;; Author: Masahiro Hayashi <mhayashi1120@gmail.com>
;; Keywords: encrypt decrypt password Rijndael
;; URL: http://github.com/mhayashi1120/Emacs-cipher/raw/master/cipher/aes.el
;; Emacs: GNU Emacs 22 or later
;; Version 0.8.5

(defconst cipher/aes-version "0.8.5")

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

;; Put this file into load-path'ed directory, and 
;; !!!!!!!!!!!!!!! BYTE COMPILE IT !!!!!!!!!!!!!!!
;; And put the following expression into your .emacs.
;;
;;     (require 'cipher/aes)

;;; Usage:

;; * To encode a well encoded string (High level API)
;; `cipher/aes-encrypt-string' <-> `cipher/aes-decrypt-string'
;;
;; * To encode a unibyte string with algorithm (Low level API)
;; `cipher/aes-encrypt' <-> `cipher/aes-decrypt'
;;
;;; Sample:

;; * To encrypt my secret
;;   Please ensure that do not forget `clear-string' you want to hide.

;; (defvar my-secret nil)

;; (let ((raw-string "My Secret"))
;;   (setq my-secret (cipher/aes-encrypt-string raw-string))
;;   (clear-string raw-string))

;; * To decrypt `my-secret'

;; (cipher/aes-decrypt-string my-secret)

;;; TODO:
;; * about algorithm
;; http://csrc.nist.gov/archive/aes/index.html
;; Rijndael algorithm

;; * cleanup temporary vector? or simply garbage-collect?

;;; Code:

(eval-when-compile
  (require 'cl))

(defgroup cipher/aes nil
  "Encrypt/Decrypt string with password"
  :group 'environment)

(defcustom cipher/aes-algorithm "aes-256-cbc"
  "Cipher algorithm to encrypt a message.
Following algorithms are supported.

aes-256-ecb, aes-192-ecb, aes-128-ecb,
aes-256-cbc, aes-192-cbc, aes-128-cbc
"
  :group 'cipher/aes
  :type 'string)

(defun cipher/aes-encrypt-string (string)
  "Encrypt a well encoded STRING to encrypted string 
which can be decrypted by `cipher/aes-decrypt-string'."
  (cipher/aes-encrypt (encode-coding-string string default-terminal-coding-system)))

(defun cipher/aes-decrypt-string (encrypted-string)
  "Decrypt a ENCRYPTED-STRING which was encrypted by `cipher/aes-encrypt-string'"
  (decode-coding-string
   (cipher/aes-decrypt encrypted-string) default-terminal-coding-system))

(defun cipher/aes-encrypt (unibyte-string &optional algorithm)
  "Encrypt a UNIBYTE-STRING with ALGORITHM.
See `cipher/aes-algorithm' list the supported ALGORITHM ."
  (cipher/aes--check-unibytes unibyte-string)
  (let* ((salt (cipher/aes--create-salt))
         (pass (cipher/aes--read-passwd "Password: " t)))
    (cipher/aes--proc algorithm
      (destructuring-bind (raw-key iv) (cipher/aes--bytes-to-key pass salt)
        (let ((key (cipher/aes--key-expansion raw-key)))
          (cipher/aes--encrypt-0 unibyte-string key salt iv))))))

(defun cipher/aes-decrypt (encrypted-string &optional algorithm)
  "Decrypt a ENCRYPTED-STRING which was encrypted by `cipher/aes-encrypt'"
  (cipher/aes--check-encrypted encrypted-string)
  (let ((algorithm (or algorithm (get-text-property 0 'encrypted-algorithm encrypted-string))))
    (cipher/aes--proc algorithm
      (destructuring-bind (salt encrypted-string) (cipher/aes--parse-salt encrypted-string)
        (let ((pass (cipher/aes--read-passwd "Password: ")))
          (destructuring-bind (raw-key iv) (cipher/aes--bytes-to-key pass salt)
            (let ((key (cipher/aes--key-expansion raw-key)))
              (cipher/aes--decrypt-0 encrypted-string key iv))))))))

(defun cipher/aes-encrypt-by-key (unibyte-string algorithm key)
  "Encrypt a UNIBYTE-STRING with ALGORITHM and KEY.
See `cipher/aes-algorithm' list the supported ALGORITHM ."
  (cipher/aes--check-unibytes unibyte-string)
  (cipher/aes--proc algorithm
    (cipher/aes--encrypt-0 unibyte-string key)))

(defun cipher/aes-decrypt-by-key (encrypted-string algorithm key)
  "Decrypt a ENCRYPTED-STRING which was encrypted by `cipher/aes-encrypt' with KEY."
  (cipher/aes--check-encrypted encrypted-string)
  (cipher/aes--proc algorithm
    (cipher/aes--decrypt-0 encrypted-string key)))

(defvar cipher/aes-password nil
  "Hiding parameter which hold password to suppress minibuffer prompt.")

(defun cipher/aes--read-passwd (prompt &optional confirm)
  (or (and (vectorp cipher/aes-password)
           ;; do not clear external password.
           (vconcat cipher/aes-password))
      (vconcat (read-passwd prompt confirm))))

(defun cipher/aes--encrypt-0 (unibyte-string key &optional salt iv)
  (cipher/aes--create-encrypted
   (apply
    'cipher/aes--unibyte-string
    (append
     (string-to-list cipher/aes--openssl-magic-word)
     salt
     (funcall cipher/aes--Enc unibyte-string key iv)))))

(defun cipher/aes--decrypt-0 (encrypted-string key &optional iv)
  (apply 
   'cipher/aes--unibyte-string
   (funcall cipher/aes--Dec encrypted-string key iv)))

(defun cipher/aes--check-unibytes (unibytes)
  (cond
   ((stringp unibytes)
    (when (multibyte-string-p unibytes)
      (error "Not a unibyte string")))
   ((vectorp unibytes))))

(defun cipher/aes--check-encrypted (encrypted-string)
  (cond
   ((stringp encrypted-string)
    (when (multibyte-string-p encrypted-string)
      (error "Not a encrypted string")))))

;; Basic utilities

(defsubst cipher/aes--word-xor (word1 word2)
  (vector 
   (logxor (aref word1 0) (aref word2 0))
   (logxor (aref word1 1) (aref word2 1))
   (logxor (aref word1 2) (aref word2 2))
   (logxor (aref word1 3) (aref word2 3))))

(defsubst cipher/aes--rot (list count)
  (loop with len = (length list)
        for i from 0 below len
        collect (nth (mod (+ i count) len) list)))

(defsubst cipher/aes--byte-rot (byte count)
  (let ((v (lsh byte count)))
    (logior
     (logand ?\xff v)
     (lsh (logand ?\xff00 v) -8))))

;; Algorithm specifications

;; section 5
;; AES-128: Nk 4 Nb 4 Nr 10
;; AES-192: Nk 6 Nb 4 Nr 12
;; AES-256: Nk 8 Nb 4 Nr 14
(defconst cipher/aes--cipher-algorithm-alist
  '(
    (aes-128 4 4 10)
    (aes-192 6 4 12)
    (aes-256 8 4 14)
    ))

(defconst cipher/aes--block-algorithm-alist
  '(
    (ecb cipher/aes--ecb-encrypt cipher/aes--ecb-decrypt 0)
    (cbc cipher/aes--cbc-encrypt cipher/aes--cbc-decrypt cipher/aes--Block)
    ))

;; section 6.3
;; Block size
(defvar cipher/aes--Nb 4)

;; section 6.3
;; Key length
(defvar cipher/aes--Nk)

;; section 6.3
;; Number of rounds
(defvar cipher/aes--Nr)

(defvar cipher/aes--Enc)
(defvar cipher/aes--Dec)

;; count of row in State
(defconst cipher/aes--Row 4)
;; size of State
(defvar cipher/aes--Block)
;; size of IV (Initial Vector)
(defvar cipher/aes--IV)

(defvar cipher/aes--Algorithm)

(defun cipher/aes--parse-algorithm (name)
  (unless (string-match "^\\(aes-\\(?:128\\|192\\|256\\)\\)-\\(ecb\\|cbc\\)$" name)
    (error "%s is not supported" name))
  (list (intern (match-string 1 name)) 
        (intern (match-string 2 name))))

(defun cipher/aes--create-encrypted (string)
  (propertize string 'encrypted-algorithm cipher/aes--Algorithm))

(defmacro cipher/aes--cipher-algorithm (algorithm &rest form)
  (declare (indent 1))
  (let ((cell (make-symbol "cell")))
    `(let ((,cell (assq ,algorithm cipher/aes--cipher-algorithm-alist)))
       (unless ,cell
         (error "%s is not supported" ,algorithm))
       (let* ((cipher/aes--Nk (nth 1 ,cell))
              (cipher/aes--Nb (nth 2 ,cell))
              (cipher/aes--Nr (nth 3 ,cell))
              (cipher/aes--Block (* cipher/aes--Nb cipher/aes--Row)))
         ,@form))))

(defmacro cipher/aes--block-algorithm (algorithm &rest form)
  (declare (indent 1))
  (let ((cell (make-symbol "cell")))
    `(let ((,cell (assq ,algorithm cipher/aes--block-algorithm-alist)))
       (unless ,cell
         (error "%s is not supported" ,algorithm))
       (let* ((cipher/aes--Enc (nth 1 ,cell))
              (cipher/aes--Dec (nth 2 ,cell))
              (cipher/aes--IV (eval (nth 3 ,cell))))
         ,@form))))

(defmacro cipher/aes--proc (algorithm &rest form)
  (declare (indent 1))
  (let ((cipher (make-symbol "cipher"))
        (block-mode (make-symbol "block-mode")))
    `(let ((cipher/aes--Algorithm (or ,algorithm cipher/aes-algorithm)))
       (destructuring-bind (cipher block) (cipher/aes--parse-algorithm cipher/aes--Algorithm)
         (cipher/aes--cipher-algorithm cipher
           (cipher/aes--block-algorithm block
             ,@form))))))

;;
;; bit/number operation for Emacs
;;

(defsubst cipher/aes--unibytes-to-state (unibytes)
  (loop for r from 0 below cipher/aes--Row
        with state = (make-vector cipher/aes--Row nil)
        with len = (length unibytes)
        with suffix-len = (- cipher/aes--Block len)
        do (loop for c from 0 below cipher/aes--Nb
                 with from = (* cipher/aes--Nb r)
                 with word = (make-vector cipher/aes--Nb suffix-len)
                 initially (aset state r word)
                 while (< (+ from c) len)
                 ;; word in unibytes
                 ;; if unibytes are before encrypted, state suffixed by length
                 ;; of rest of State
                 do (aset word c (aref unibytes (+ from c))))
        finally return state))

(defsubst cipher/aes--parse-unibytes (unibyte-string pos)
  (let* ((len (length unibyte-string))
         (end-pos (min len (+ pos cipher/aes--Block)))
         (state (cipher/aes--unibytes-to-state (substring unibyte-string pos end-pos)))
         (rest (if (and (= len end-pos) 
                        (< (- end-pos pos) cipher/aes--Block))
                   nil end-pos)))
    (list state rest)))

(defsubst cipher/aes--parse-encrypted (encrypted-string pos)
  (let* ((len (length encrypted-string))
         (end-pos (min len (+ pos cipher/aes--Block)))
         (state (cipher/aes--unibytes-to-state (substring encrypted-string pos end-pos)))
         (rest (if (= len end-pos) nil end-pos)))
    (list state rest)))

(defsubst cipher/aes--state-to-bytes (state)
  (loop for i from 0 below (* cipher/aes--Row cipher/aes--Nb)
        collect 
        (let ((r (/ i cipher/aes--Row))
              (c (% i cipher/aes--Nb)))
          (aref (aref state r) c))))

(defsubst cipher/aes--state-clone (state)
  (loop for r across state
        for i from 0
        with v = (vconcat state)
        do (aset v i (vconcat r))
        finally return v))

(defconst cipher/aes--pkcs5-salt-length 8)
(defconst cipher/aes--openssl-magic-word "Salted__")

(defun cipher/aes--create-salt ()
  (loop for i from 0 below cipher/aes--pkcs5-salt-length
        with salt = (make-vector cipher/aes--pkcs5-salt-length nil)
        do (aset salt i (random ?\x100))
        finally return salt))

(defun cipher/aes--parse-salt (unibyte-string)
  (let ((regexp (format "^%s\\([\000-\377]\\{%d\\}\\)"
                        cipher/aes--openssl-magic-word cipher/aes--pkcs5-salt-length)))
    (unless (string-match regexp unibyte-string)
      (error "No salted"))
    (list
     (vconcat (match-string 1 unibyte-string))
     (substring unibyte-string (match-end 0)))))

;; Emulate openssl EVP_BytesToKey function
;; return '(key iv)
(defun cipher/aes--bytes-to-key (data &optional salt)
  (let ((iv (make-vector cipher/aes--IV nil))
        (key (make-vector (* cipher/aes--Nk cipher/aes--Nb) nil))
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
            (cipher/aes--key-md5-digest hash context)
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

(defun cipher/aes--key-md5-digest (hash data)
  (loop for v across (cipher/aes--hex-to-vector (md5 (apply 'cipher/aes--unibyte-string data)))
        for i from 0
        do (aset hash i v)))

(defun cipher/aes--hex-to-vector (hex-string)
  (vconcat
   (loop for i from 0 below (length hex-string) by 2
         collect (string-to-number (substring hex-string i (+ i 2)) 16))))

(if (fboundp 'unibyte-string)
    (defalias 'cipher/aes--unibyte-string 'unibyte-string)
  (defun cipher/aes--unibyte-string (&rest bytes)
    (concat bytes)))

;;
;; AES Algorithm defined functions
;;

;; 4.1 Addition
(defsubst cipher/aes--add (&rest numbers)
  (apply 'logxor numbers))

;; 4.2 Multiplication
;; 4.2.1 xtime
(defconst cipher/aes--xtime-cache
  (loop for byte from 0 below ?\x100
        with table = (make-vector ?\x100 nil)
        do (aset table byte 
                 (if (< byte ?\x80)
                     (lsh byte 1)
                   (logand (logxor (lsh byte 1) ?\x11b) ?\xff)))
        finally return table))

(defun cipher/aes--xtime (byte)
  (aref cipher/aes--xtime-cache byte))

(defconst cipher/aes--multiply-log
  (loop for i from 0 to ?\xff
        with table = (make-vector ?\x100 nil)
        do 
        (loop for j from 1 to 7
              with l = (make-vector 8 nil)
              with v = i
              initially (progn
                          (aset table i l)
                          (aset l 0 i))
              do (let ((n (cipher/aes--xtime v)))
                   (aset l j n)
                   (setq v n)))
        finally return table))

(defun cipher/aes--multiply-0 (byte1 byte2)
  (let ((table (aref cipher/aes--multiply-log byte1)))
    (apply 'cipher/aes--add
           (loop for i from 0 to 7
                 unless (zerop (logand byte2 (lsh 1 i)))
                 collect (aref table i)))))

(defconst cipher/aes--multiply-cache 
  (vconcat
   (loop for b1 from 0 to ?\xff
         collect 
         (vconcat (loop for b2 from 0 to ?\xff
                        collect (cipher/aes--multiply-0 b1 b2))))))

(defsubst cipher/aes--multiply (byte1 byte2)
  (aref (aref cipher/aes--multiply-cache byte1) byte2))

(defconst cipher/aes--inv-multiply-cache
  (loop with v = (make-vector 256 nil)
        for byte from 0 to 255
        do (aset v byte
                 (loop for b across (aref cipher/aes--multiply-cache byte)
                       for i from 0
                       if (= b 1)
                       return i
                       finally return 0))
        finally return v))

(defsubst cipher/aes--inv-multiply (byte)
  (aref cipher/aes--inv-multiply-cache byte))

;; section 5.2
(defsubst cipher/aes--rot-word (word)
  (vector
   (aref word 1)
   (aref word 2)
   (aref word 3)
   (aref word 0)))

(defsubst cipher/aes--sub-word (word)
  (vector
   (aref cipher/aes--S-box (aref word 0))
   (aref cipher/aes--S-box (aref word 1))
   (aref cipher/aes--S-box (aref word 2))
   (aref cipher/aes--S-box (aref word 3))))

(defun cipher/aes--key-expansion (key)
  (let (res)
    (loop for i from 0 below cipher/aes--Nk
          do 
          (setq res (cons  
                     (loop for j from 0 below cipher/aes--Nb
                           with w = (make-vector cipher/aes--Nb nil)
                           do (aset w j (aref key (+ j (* cipher/aes--Nb i))))
                           finally return w)
                     res)))
    (loop for i from cipher/aes--Nk below (* cipher/aes--Nb (1+ cipher/aes--Nr))
          do (let ((temp (car res)))
               (cond
                ((= (mod i cipher/aes--Nk) 0)
                 (setq temp (cipher/aes--word-xor 
                             (cipher/aes--sub-word
                              (cipher/aes--rot-word temp))
                             ;; `i' is start from 1
                             (aref cipher/aes--Rcon (1- (/ i cipher/aes--Nk))))))
                ((and (> cipher/aes--Nk 6)
                      (= (mod i cipher/aes--Nk) 4))
                 (setq temp (cipher/aes--sub-word temp))))
               (setq res (cons
                          (cipher/aes--word-xor 
                           (nth (1- cipher/aes--Nk) res)
                           temp)
                          res))))
    (nreverse res)))

;; section 5.1.4
(defsubst cipher/aes--add-round-key (state key)
  (aset state 0 (cipher/aes--word-xor (aref state 0) (aref key 0)))
  (aset state 1 (cipher/aes--word-xor (aref state 1) (aref key 1)))
  (aset state 2 (cipher/aes--word-xor (aref state 2) (aref key 2)))
  (aset state 3 (cipher/aes--word-xor (aref state 3) (aref key 3)))
  state)

(defsubst cipher/aes--round-key (key n)
  (let ((rest (nthcdr n key)))
    (vector
     (nth 0 rest)
     (nth 1 rest)
     (nth 2 rest)
     (nth 3 rest))))

;; section 5.1.3
(defsubst cipher/aes--mix-column (word)
  (let ((w1 (vconcat word))
        (w2 (vconcat (mapcar 
                      (lambda (b)
                        (cipher/aes--multiply b 2))
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

(defsubst cipher/aes--mix-columns (state)
  (cipher/aes--mix-column (aref state 0))
  (cipher/aes--mix-column (aref state 1))
  (cipher/aes--mix-column (aref state 2))
  (cipher/aes--mix-column (aref state 3))
  state)

;; section 5.3.3
(defsubst cipher/aes--inv-mix-column (word)
  (let ((w1 (vconcat word))
        (w2 (vconcat (mapcar (lambda (b) (cipher/aes--multiply b 2)) word)))
        (w4 (vconcat (mapcar (lambda (b) (cipher/aes--multiply b 4)) word)))
        (w8 (vconcat (mapcar (lambda (b) (cipher/aes--multiply b 8)) word))))
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

(defsubst cipher/aes--inv-mix-columns (state)
  (cipher/aes--inv-mix-column (aref state 0))
  (cipher/aes--inv-mix-column (aref state 1))
  (cipher/aes--inv-mix-column (aref state 2))
  (cipher/aes--inv-mix-column (aref state 3))
  state)

(defvar cipher/aes--Rcon
  (vconcat
   (loop repeat 10
         for v = 1 then (cipher/aes--xtime v)
         collect (vector v 0 0 0))))

;; for section 5.1.2, 5.3.1
(defsubst cipher/aes--shift-row (state row count)
  (let ((new-rows (loop for col from 0 below cipher/aes--Nb
                        collect 
                        (aref (aref state (mod (+ col count) cipher/aes--Nb)) row))))
    (loop for col from 0 below cipher/aes--Nb
          for new-row in new-rows
          do
          (aset (aref state col) row new-row))))

;; section 5.1.2
(defsubst cipher/aes--shift-rows (state)
  ;; ignore first row
  (cipher/aes--shift-row state 1 1)
  (cipher/aes--shift-row state 2 2)
  (cipher/aes--shift-row state 3 3)
  state)

;; section 5.3.1
(defsubst cipher/aes--inv-shift-rows (state)
  ;; ignore first row
  (cipher/aes--shift-row state 1 3)
  (cipher/aes--shift-row state 2 2)
  (cipher/aes--shift-row state 3 1)
  state)

;; section 5.1.1
(defun cipher/aes--s-box-0 (byte)
  (let* ((inv (cipher/aes--inv-multiply byte))
         (s inv)
         (x inv))
    (loop repeat 4
          do (progn
               (setq s (cipher/aes--byte-rot s 1))
               (setq x (logxor s x))))
    (logxor x ?\x63)))

(defconst cipher/aes--S-box
  (loop for b from 0 to ?\xff
        with box = (make-vector ?\x100 nil)
        do (aset box b (cipher/aes--s-box-0 b))
        finally return box))

(defsubst cipher/aes--sub-bytes (state)
  (loop for w across state
        do (progn 
             (aset w 0 (aref cipher/aes--S-box (aref w 0)))
             (aset w 1 (aref cipher/aes--S-box (aref w 1)))
             (aset w 2 (aref cipher/aes--S-box (aref w 2)))
             (aset w 3 (aref cipher/aes--S-box (aref w 3)))))
  state)

;; section 5.3.2
(defconst cipher/aes--inv-S-box
  (loop for s across cipher/aes--S-box
        for b from 0
        with ibox = (make-vector ?\x100 nil)
        do (aset ibox s b)
        finally return ibox))

(defsubst cipher/aes--inv-sub-bytes (state)
  (loop for w across state
        do (progn 
             (aset w 0 (aref cipher/aes--inv-S-box (aref w 0)))
             (aset w 1 (aref cipher/aes--inv-S-box (aref w 1)))
             (aset w 2 (aref cipher/aes--inv-S-box (aref w 2)))
             (aset w 3 (aref cipher/aes--inv-S-box (aref w 3)))))
  state)

;; section 5.1
(defsubst cipher/aes--cipher (state key)
  (cipher/aes--add-round-key state (cipher/aes--round-key key 0))
  (loop for round from 1 to (1- cipher/aes--Nr)
        do (progn
             (cipher/aes--sub-bytes state)
             (cipher/aes--shift-rows state)
             (cipher/aes--mix-columns state)
             (cipher/aes--add-round-key 
              state (cipher/aes--round-key key (* round cipher/aes--Nb)))))
  (cipher/aes--sub-bytes state)
  (cipher/aes--shift-rows state)
  (cipher/aes--add-round-key
   state (cipher/aes--round-key key (* cipher/aes--Nr cipher/aes--Nb)))
  state)

;; section 5.3 
(defsubst cipher/aes--inv-cipher (state key)
  (cipher/aes--add-round-key state 
                      (cipher/aes--round-key key (* cipher/aes--Nr cipher/aes--Nb)))
  (loop for round downfrom (1- cipher/aes--Nr) to 1
        do (progn
             (cipher/aes--inv-shift-rows state)
             (cipher/aes--inv-sub-bytes state)
             (cipher/aes--add-round-key 
              state (cipher/aes--round-key key (* round cipher/aes--Nb)))
             (cipher/aes--inv-mix-columns state)))
  (cipher/aes--inv-shift-rows state)
  (cipher/aes--inv-sub-bytes state)
  (cipher/aes--add-round-key
   state (cipher/aes--round-key key 0))
  state)

;;
;; Block mode Algorithm 
;;

(defun cipher/aes--cbc-encrypt (unibyte-string key iv)
  (loop with pos = 0
        with state-1 = (cipher/aes--unibytes-to-state iv)
        append (let* ((parsed (cipher/aes--parse-unibytes unibyte-string pos))
                      (state-d0 (cipher/aes--cbc-state-xor state-1 (nth 0 parsed)))
                      (state-e0 (cipher/aes--cipher state-d0 key)))
                 (setq pos (nth 1 parsed))
                 (setq state-1 state-e0)
                 (cipher/aes--state-to-bytes state-e0))
        while pos))

(defun cipher/aes--cbc-decrypt (encrypted-string key iv)
  (cipher/aes--check-encrypted-string encrypted-string)
  (loop with pos = 0
        with state-1 = (cipher/aes--unibytes-to-state iv)
        append (let* ((parsed (cipher/aes--parse-encrypted encrypted-string pos))
                      (state-e (nth 0 parsed))
                      ;; Clone state cause of `cipher/aes--inv-cipher' have side-effect
                      (state-e0 (cipher/aes--state-clone state-e))
                      (state-d0 (cipher/aes--cbc-state-xor state-1 (cipher/aes--inv-cipher state-e key)))
                      (bytes (cipher/aes--state-to-bytes state-d0)))
                 (setq pos (nth 1 parsed))
                 (setq state-1 state-e0)
                 (unless pos
                   (setq bytes (cipher/aes--check-end-of-decrypted bytes)))
                 (append bytes nil))
        while pos))

(defun cipher/aes--cbc-state-xor (state-1 state0)
  (loop for w1 across state-1
        for w2 across state0
        for i from 0
        with state = (make-vector cipher/aes--Row nil)
        do (aset state i (cipher/aes--word-xor w1 w2))
        finally return state))

;; check End-Of-Block bytes
(defun cipher/aes--check-end-of-decrypted (eob-bytes)
  (let* ((pad (car (last eob-bytes)))
         (valid-len (- cipher/aes--Block pad)))
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

(defun cipher/aes--check-encrypted-string (string)
  (unless (= (mod (length string) cipher/aes--Block) 0)
    (error "Bad decrypt")))

(defun cipher/aes--ecb-encrypt (unibyte-string key &rest dummy)
  (loop with pos = 0
        append (let* ((parse (cipher/aes--parse-unibytes unibyte-string pos))
                      (in-state (nth 0 parse))
                      (out-state (cipher/aes--cipher in-state key)))
                 (setq pos (nth 1 parse))
                 (cipher/aes--state-to-bytes out-state))
        while pos))

(defun cipher/aes--ecb-decrypt (encrypted-string key &rest dummy)
  (cipher/aes--check-encrypted-string encrypted-string)
  (loop with pos = 0
        append (let* ((parse (cipher/aes--parse-encrypted encrypted-string pos))
                      (in-state (nth 0 parse))
                      (out-state (cipher/aes--inv-cipher in-state key))
                      (bytes (cipher/aes--state-to-bytes out-state)))
                 (setq pos (nth 1 parse))
                 (unless pos
                   (setq bytes (cipher/aes--check-end-of-decrypted bytes)))
                 (append bytes nil))
        while pos))

(provide 'cipher/aes)

;;; cipher/aes.el ends here
