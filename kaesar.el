;;; kaesar.el --- Another AES encryptin/decryptin string with password.

;; Author: Masahiro Hayashi <mhayashi1120@gmail.com>
;; Keywords: data
;; URL: http://github.com/mhayashi1120/Emacs-cipher/raw/master/kaesar.el
;; Emacs: GNU Emacs 22 or later
;; Version: 0.1.0
;; Package-Requires: ()

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
;; (require 'kaesar)
;;

;;; Commentary:

;; This package provides AES algorithm to encrypt/decrypt Emacs
;; string. Supported algorithm desired to get interoperability with
;; openssl. You can get decrypted text if you don't forget password.

;; Why kaesar?
;; This package previously named 'cipher/aes' but ELPA cannot handle
;; such package name.  So, I had to change the name but `aes' package
;; already exists. (That is faster than this package!)  I continue to
;; consider the new name which contains "aes" string. There is the
;; ancient cipher algorithm caesar
;; http://en.wikipedia.org/wiki/Caesar_cipher
;;  K`aes'ar is change the first character of Caesar There is no
;; meaning more than containing `aes' word.

;;; Usage:

;; * To encode a well encoded string (High level API)
;; `kaesar-encrypt-string' <-> `kaesar-decrypt-string'
;;
;; * To encode a unibyte string with algorithm (Low level API)
;; `kaesar-encrypt' <-> `kaesar-decrypt'
;;
;;; Sample:

;; * To encrypt my secret
;;   Please ensure that do not forget `clear-string' you want to hide.

;; (defvar my-secret nil)

;; (let ((raw-string "My Secret"))
;;   (setq my-secret (kaesar-encrypt-string raw-string))
;;   (clear-string raw-string))

;; * To decrypt `my-secret'

;; (kaesar-decrypt-string my-secret)

;;; TODO:
;; * about algorithm
;; http://csrc.nist.gov/archive/aes/rijndael/wsdindex.html
;; Rijndael algorithm

;; * cleanup temporary vector? or simply garbage-collect?

;; * CTR mode

;; * validation -> AESAVS.pdf

;;; Code:

(eval-when-compile
  (require 'cl))

(defgroup kaesar nil
  "Encrypt/Decrypt string with password"
  :group 'environment)

(defcustom kaesar-algorithm "aes-256-cbc"
  "Cipher algorithm to encrypt a message.
Following algorithms are supported.

aes-256-ecb, aes-192-ecb, aes-128-ecb,
aes-256-cbc, aes-192-cbc, aes-128-cbc
"
  :group 'kaesar
  :type 'string)

(defcustom kaesar-encrypt-prompt nil
  "Password prompt when read password to encrypt."
  :group 'kaesar
  :type 'string)

(defcustom kaesar-decrypt-prompt nil
  "Password prompt when read password to decrypt."
  :group 'kaesar
  :type 'string)

(defvar kaesar--Enc)
(defvar kaesar--Dec)

(defmacro kaesar--proc (algorithm &rest form)
  (declare (indent 1))
  (let ((cipher (make-symbol "cipher"))
        (block-mode (make-symbol "block-mode")))
    `(let ((kaesar--Algorithm (or ,algorithm kaesar-algorithm)))
       (destructuring-bind (,cipher ,block-mode)
           (kaesar--parse-algorithm kaesar--Algorithm)
         (kaesar--cipher-algorithm ,cipher
           (kaesar--block-algorithm ,block-mode
             ,@form))))))

(defvar kaesar-password nil
  "To suppress the minibuffer prompt.
This is a hiding parameter which hold password as vector.")

(defun kaesar--read-passwd (prompt &optional confirm)
  (or (and (vectorp kaesar-password)
           ;; do not clear external password.
           (vconcat kaesar-password))
      (vconcat (read-passwd prompt confirm))))

(defun kaesar--check-unibytes (unibytes)
  (cond
   ((stringp unibytes)
    (when (multibyte-string-p unibytes)
      (error "Not a unibyte string")))
   ((vectorp unibytes))))

(defun kaesar--check-encrypted (encbyte-string)
  (cond
   ((stringp encbyte-string)
    (when (multibyte-string-p encbyte-string)
      (error "Not a encrypted string")))))

;; Basic utilities

(defsubst kaesar--word-xor! (word1 word2)
  (aset word1 0 (logxor (aref word1 0) (aref word2 0)))
  (aset word1 1 (logxor (aref word1 1) (aref word2 1)))
  (aset word1 2 (logxor (aref word1 2) (aref word2 2)))
  (aset word1 3 (logxor (aref word1 3) (aref word2 3))))

(defsubst kaesar--byte-rot (byte count)
  (let ((v (lsh byte count)))
    (logior
     (logand ?\xff v)
     (lsh (logand ?\xff00 v) -8))))

;; Algorithm specifications

;; AES-128: Nk 4 Nb 4 Nr 10
;; AES-192: Nk 6 Nb 4 Nr 12
;; AES-256: Nk 8 Nb 4 Nr 14
(defconst kaesar--cipher-algorithm-alist
  '(
    (aes-128 4 4 10)
    (aes-192 6 4 12)
    (aes-256 8 4 14)
    ))

(defconst kaesar--block-algorithm-alist
  '(
    (ecb kaesar--ecb-encrypt kaesar--ecb-decrypt 0)
    (cbc kaesar--cbc-encrypt kaesar--cbc-decrypt kaesar--Block)
    ))

;; Block size
(defvar kaesar--Nb 4)

;; Key length
(defvar kaesar--Nk)

;; Number of rounds
(defvar kaesar--Nr)

;; count of row in State
(defconst kaesar--Row 4)
;; size of State
(defvar kaesar--Block)
;; size of IV (Initial Vector)
(defvar kaesar--IV)

(defvar kaesar--Algorithm)

(defconst kaesar--pkcs5-salt-length 8)
(defconst kaesar--openssl-magic-word "Salted__")

(defun kaesar--encrypt-0 (unibyte-string raw-key &optional salt iv)
  (let* ((key (kaesar--key-expansion raw-key))
         (salt-magic (string-to-list kaesar--openssl-magic-word))
         (encrypted (funcall kaesar--Enc unibyte-string key iv))
         (full-data (append salt-magic salt encrypted))
         (unibytes (apply 'kaesar--unibyte-string full-data)))
    (kaesar--create-encrypted unibytes)))

(defun kaesar--decrypt-0 (encbyte-string raw-key &optional iv)
  (let* ((key (kaesar--key-expansion raw-key))
         (decrypted (funcall kaesar--Dec encbyte-string key iv)))
    (apply 'kaesar--unibyte-string decrypted)))

(defun kaesar--parse-algorithm (name)
  (unless (string-match "^\\(aes-\\(?:128\\|192\\|256\\)\\)-\\(ecb\\|cbc\\)$" name)
    (error "%s is not supported" name))
  (list (intern (match-string 1 name))
        (intern (match-string 2 name))))

(defun kaesar--create-encrypted (string)
  (propertize string 'encrypted-algorithm kaesar--Algorithm))

(defmacro kaesar--cipher-algorithm (algorithm &rest form)
  (declare (indent 1))
  (let ((cell (make-symbol "cell")))
    `(let ((,cell (assq ,algorithm kaesar--cipher-algorithm-alist)))
       (unless ,cell
         (error "%s is not supported" ,algorithm))
       (let* ((kaesar--Nk (nth 1 ,cell))
              (kaesar--Nb (nth 2 ,cell))
              (kaesar--Nr (nth 3 ,cell))
              (kaesar--Block (* kaesar--Nb kaesar--Row)))
         ,@form))))

(defmacro kaesar--block-algorithm (algorithm &rest form)
  (declare (indent 1))
  (let ((cell (make-symbol "cell")))
    `(let ((,cell (assq ,algorithm kaesar--block-algorithm-alist)))
       (unless ,cell
         (error "%s is not supported" ,algorithm))
       (let* ((kaesar--Enc (nth 1 ,cell))
              (kaesar--Dec (nth 2 ,cell))
              (kaesar--IV (eval (nth 3 ,cell))))
         ,@form))))

;;
;; bit/number operation for Emacs
;;

(defsubst kaesar--unibytes-to-state (unibytes)
  (loop for r from 0 below kaesar--Row
        with state = (make-vector kaesar--Row nil)
        with len = (length unibytes)
        with suffix-len = (- kaesar--Block len)
        do (loop for c from 0 below kaesar--Nb
                 with from = (* kaesar--Nb r)
                 with word = (make-vector kaesar--Nb suffix-len)
                 initially (aset state r word)
                 while (< (+ from c) len)
                 ;; word in unibytes
                 ;; if unibytes are before encrypted, state suffixed by length
                 ;; of rest of State
                 do (aset word c (aref unibytes (+ from c))))
        finally return state))

(defsubst kaesar--read-unibytes (unibyte-string pos)
  (let* ((len (length unibyte-string))
         (end-pos (min len (+ pos kaesar--Block)))
         (state (kaesar--unibytes-to-state (substring unibyte-string pos end-pos)))
         (rest (if (and (= len end-pos)
                        (< (- end-pos pos) kaesar--Block))
                   nil end-pos)))
    (list state rest)))

(defsubst kaesar--read-encbytes (encbyte-string pos)
  (let* ((len (length encbyte-string))
         (end-pos (min len (+ pos kaesar--Block)))
         (state (kaesar--unibytes-to-state (substring encbyte-string pos end-pos)))
         (rest (if (= len end-pos) nil end-pos)))
    (list state rest)))

(defsubst kaesar--state-to-bytes (state)
  (loop for i from 0 below (* kaesar--Row kaesar--Nb)
        collect
        (let ((r (/ i kaesar--Row))
              (c (% i kaesar--Nb)))
          (aref (aref state r) c))))

(defsubst kaesar--state-clone (state)
  (loop for r across state
        for i from 0
        with v = (vconcat state)
        do (aset v i (vconcat r))
        finally return v))

(defun kaesar--create-salt ()
  (loop for i from 0 below kaesar--pkcs5-salt-length
        with salt = (make-vector kaesar--pkcs5-salt-length nil)
        do (aset salt i (random ?\x100))
        finally return salt))

(defun kaesar--parse-salt (unibyte-string)
  (let ((regexp (format "^%s\\([\000-\377]\\{%d\\}\\)"
                        kaesar--openssl-magic-word kaesar--pkcs5-salt-length)))
    (unless (string-match regexp unibyte-string)
      (error "No salted"))
    (list
     (vconcat (match-string 1 unibyte-string))
     (substring unibyte-string (match-end 0)))))

(defcustom kaesar-password-to-key-function
  'kaesar--openssl-evp-bytes-to-key
  "Function which accepts password and optional salt,
to create AES key and initial vector."
  :group 'kaesar
  :type 'function)

;; password -> '(key iv)
(defun kaesar--bytes-to-key (data &optional salt)
  (funcall kaesar-password-to-key-function data salt))

;; Emulate openssl EVP_BytesToKey function
(defun kaesar--openssl-evp-bytes-to-key (data &optional salt)
  (let ((iv (make-vector kaesar--IV nil))
        (key (make-vector (* kaesar--Nk kaesar--Nb) nil))
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
            (kaesar--key-md5-digest hash context)
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
    ;; clear raw password text
    (fillarray data nil)
    (list key iv)))

(defun kaesar--key-md5-digest (hash data)
  (loop with unibytes = (apply 'kaesar--unibyte-string data)
        with md5-hash = (md5 unibytes)
        for v across (kaesar--hex-to-vector md5-hash)
        for i from 0
        do (aset hash i v)))

(defun kaesar--hex-to-vector (hex-string)
  (loop for i from 0 below (length hex-string) by 2
        collect (string-to-number (substring hex-string i (+ i 2)) 16)
        into res
        finally return (vconcat res)))

(if (fboundp 'unibyte-string)
    (defalias 'kaesar--unibyte-string 'unibyte-string)
  (defun kaesar--unibyte-string (&rest bytes)
    (concat bytes)))

;;
;; AES Algorithm defined functions
;;

;; 4.1 Addition
(defsubst kaesar--add (&rest numbers)
  (apply 'logxor numbers))

;; 4.2 Multiplication
;; 4.2.1 xtime
(defconst kaesar--xtime-cache
  (eval-when-compile
    (loop for byte from 0 below ?\x100
          with table = (make-vector ?\x100 nil)
          do (aset table byte
                   (if (< byte ?\x80)
                       (lsh byte 1)
                     (logand (logxor (lsh byte 1) ?\x11b) ?\xff)))
          finally return table)))

(defun kaesar--xtime (byte)
  (aref kaesar--xtime-cache byte))

(defconst kaesar--multiply-log
  (eval-when-compile
    (loop for i from 0 to ?\xff
          with table = (make-vector ?\x100 nil)
          do
          (loop for j from 1 to 7
                with l = (make-vector 8 nil)
                with v = i
                initially (progn
                            (aset table i l)
                            (aset l 0 i))
                do (let ((n (kaesar--xtime v)))
                     (aset l j n)
                     (setq v n)))
          finally return table)))

(defun kaesar--multiply-0 (byte1 byte2)
  (let ((table (aref kaesar--multiply-log byte1)))
    (apply 'kaesar--add
           (loop for i from 0 to 7
                 unless (zerop (logand byte2 (lsh 1 i)))
                 collect (aref table i)))))

(defconst kaesar--multiply-cache
  (eval-when-compile
    (loop for b1 from 0 to ?\xff
          collect
          (loop for b2 from 0 to ?\xff
                collect (kaesar--multiply-0 b1 b2) into res
                finally return (vconcat res))
          into res
          finally return (vconcat res))))

(defsubst kaesar--multiply (byte1 byte2)
  (aref (aref kaesar--multiply-cache byte1) byte2))

(defconst kaesar--S-box
  (eval-when-compile
    (loop with inv-cache =
          (loop with v = (make-vector 256 nil)
                for byte from 0 to 255
                do (aset v byte
                         (loop for b across (aref kaesar--multiply-cache byte)
                               for i from 0
                               if (= b 1)
                               return i
                               finally return 0))
                finally return v)
          with boxing = (lambda (byte)
                          (let* ((inv (aref inv-cache byte))
                                 (s inv)
                                 (x inv))
                            (loop repeat 4
                                  do (progn
                                       (setq s (kaesar--byte-rot s 1))
                                       (setq x (logxor s x))))
                            (logxor x ?\x63)))
          for b from 0 to ?\xff
          with box = (make-vector ?\x100 nil)
          do (aset box b (funcall boxing b))
          finally return box)))

(defsubst kaesar--sub-word! (word)
  (aset word 0 (aref kaesar--S-box (aref word 0)))
  (aset word 1 (aref kaesar--S-box (aref word 1)))
  (aset word 2 (aref kaesar--S-box (aref word 2)))
  (aset word 3 (aref kaesar--S-box (aref word 3)))
  word)

(defsubst kaesar--sub-bytes! (state)
  (loop for w across state
        do (kaesar--sub-word! w))
  state)

(defsubst kaesar--rot-word! (word)
  (let ((b0 (aref word 0)))
    (aset word 0 (aref word 1))
    (aset word 1 (aref word 2))
    (aset word 2 (aref word 3))
    (aset word 3 b0)
    word))

(defconst kaesar--Rcon
  (eval-when-compile
    (loop repeat 10
          for v = 1 then (kaesar--xtime v)
          collect (vector v 0 0 0) into res
          finally return (vconcat res))))

(defun kaesar--key-expansion (key)
  (let (res)
    (loop for i from 0 below kaesar--Nk
          do
          (setq res (cons
                     (loop for j from 0 below kaesar--Nb
                           with w = (make-vector kaesar--Nb nil)
                           do (aset w j (aref key (+ j (* kaesar--Nb i))))
                           finally return w)
                     res)))
    (loop for i from kaesar--Nk below (* kaesar--Nb (1+ kaesar--Nr))
          do (let ((word (vconcat (car res))))
               (cond
                ((= (mod i kaesar--Nk) 0)
                 (kaesar--rot-word! word)
                 (kaesar--sub-word! word)
                 (kaesar--word-xor!
                  word
                  ;; `i' is start from 1
                  (aref kaesar--Rcon (1- (/ i kaesar--Nk)))))
                ((and (> kaesar--Nk 6)
                      (= (mod i kaesar--Nk) 4))
                 (kaesar--sub-word! word)))
               (kaesar--word-xor!
                word
                (nth (1- kaesar--Nk) res))
               (setq res (cons word res))))
    (nreverse res)))

(defsubst kaesar--add-round-key! (state key)
  (kaesar--word-xor! (aref state 0) (aref key 0))
  (kaesar--word-xor! (aref state 1) (aref key 1))
  (kaesar--word-xor! (aref state 2) (aref key 2))
  (kaesar--word-xor! (aref state 3) (aref key 3))
  state)

(defsubst kaesar--round-key (key n)
  (let ((rest (nthcdr n key)))
    (vector
     (nth 0 rest)
     (nth 1 rest)
     (nth 2 rest)
     (nth 3 rest))))

(defconst kaesar--2time-table
  (eval-when-compile
    (loop for i from 0 to ?\xff
          collect (kaesar--multiply i 2) into res
          finally return (vconcat res))))

(defconst kaesar--4time-table
  (eval-when-compile
    (loop for i from 0 to ?\xff
          collect (kaesar--multiply i 4) into res
          finally return (vconcat res))))

(defconst kaesar--8time-table
  (eval-when-compile
    (loop for i from 0 to ?\xff
          collect (kaesar--multiply i 8) into res
          finally return (vconcat res))))

(defsubst kaesar--mix-column-with-key! (word key)
  (let ((w1 (vconcat word))
        (w2 (vconcat (mapcar
                      (lambda (b)
                        (aref kaesar--2time-table b)) word))))
    ;; Coefficients of word Matrix
    ;; 2 3 1 1
    ;; 1 2 3 1
    ;; 1 1 2 3
    ;; 3 1 1 2
    (aset word 0 (logxor (aref w2 0)
                         (aref w2 1) (aref w1 1)
                         (aref w1 2)
                         (aref w1 3)
                         (aref key 0)))
    (aset word 1 (logxor (aref w1 0)
                         (aref w2 1)
                         (aref w1 2) (aref w2 2)
                         (aref w1 3)
                         (aref key 1)))
    (aset word 2 (logxor (aref w1 0)
                         (aref w1 1)
                         (aref w2 2)
                         (aref w1 3) (aref w2 3)
                         (aref key 2)))
    (aset word 3 (logxor (aref w1 0) (aref w2 0)
                         (aref w1 1)
                         (aref w1 2)
                         (aref w2 3)
                         (aref key 3)))))

;; Call mix-column and `kaesar--add-round-key!'
(defsubst kaesar--mix-columns-with-key! (state keys)
  (kaesar--mix-column-with-key! (aref state 0) (aref keys 0))
  (kaesar--mix-column-with-key! (aref state 1) (aref keys 1))
  (kaesar--mix-column-with-key! (aref state 2) (aref keys 2))
  (kaesar--mix-column-with-key! (aref state 3) (aref keys 3))
  state)

(defsubst kaesar--inv-key-with-mix-column! (key word)
  (kaesar--word-xor! word key)
  (let ((w1 (vconcat word))
        (w2 (vconcat (mapcar
                      (lambda (b)
                        (aref kaesar--2time-table b)) word)))
        (w4 (vconcat (mapcar
                      (lambda (b)
                        (aref kaesar--4time-table b)) word)))
        (w8 (vconcat (mapcar
                      (lambda (b)
                        (aref kaesar--8time-table b)) word))))
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

(defsubst kaesar--inv-key-with-mix-columns! (keys state)
  (kaesar--inv-key-with-mix-column! (aref keys 0) (aref state 0))
  (kaesar--inv-key-with-mix-column! (aref keys 1) (aref state 1))
  (kaesar--inv-key-with-mix-column! (aref keys 2) (aref state 2))
  (kaesar--inv-key-with-mix-column! (aref keys 3) (aref state 3))
  state)

(defsubst kaesar--shift-row! (state row columns)
  (let ((new-rows (mapcar
                   (lambda (col)
                     (aref (aref state col) row)) columns)))
    (loop for col from 0
          for new-val in new-rows
          do
          (aset (aref state col) row new-val))))

(defsubst kaesar--sub/shift-box! (state row columns box)
  (let ((new-rows (mapcar
                   (lambda (col)
                     (aref box (aref (aref state col) row)))
                   columns)))
    (loop for col from 0
          for new-val in new-rows
          do
          (aset (aref state col) row new-val))))

(defsubst kaesar--shift-rows! (state)
  ;; ignore first row
  (kaesar--shift-row! state 1 '(1 2 3 0))
  (kaesar--shift-row! state 2 '(2 3 0 1))
  (kaesar--shift-row! state 3 '(3 0 1 2))
  state)

(defsubst kaesar--inv-shift-rows! (state)
  ;; ignore first row
  (kaesar--shift-row! state 1 '(3 0 1 2))
  (kaesar--shift-row! state 2 '(2 3 0 1))
  (kaesar--shift-row! state 3 '(1 2 3 0))
  state)

(defconst kaesar--inv-S-box
  (eval-when-compile
    (loop for s across kaesar--S-box
          for b from 0
          with ibox = (make-vector ?\x100 nil)
          do (aset ibox s b)
          finally return ibox)))

(defsubst kaesar--inv-sub-word! (word)
  (aset word 0 (aref kaesar--inv-S-box (aref word 0)))
  (aset word 1 (aref kaesar--inv-S-box (aref word 1)))
  (aset word 2 (aref kaesar--inv-S-box (aref word 2)))
  (aset word 3 (aref kaesar--inv-S-box (aref word 3)))
  word)

(defsubst kaesar--inv-sub-bytes! (state)
  (loop for w across state
        do (kaesar--inv-sub-word! w))
  state)

(defsubst kaesar--sub-shift-mix! (key state)
  (loop for round from 1 to (1- kaesar--Nr)
        do (let ((part-key (kaesar--round-key key (* round kaesar--Nb))))
             ;; FIXME: first row only S-box
             (kaesar--sub/shift-box! state 0 '(0 1 2 3) kaesar--S-box)
             (kaesar--sub/shift-box! state 1 '(1 2 3 0) kaesar--S-box)
             (kaesar--sub/shift-box! state 2 '(2 3 0 1) kaesar--S-box)
             (kaesar--sub/shift-box! state 3 '(3 0 1 2) kaesar--S-box)
             (kaesar--mix-columns-with-key! state part-key))))

(defsubst kaesar--cipher (state key)
  (kaesar--add-round-key! state (kaesar--round-key key 0))
  (kaesar--sub-shift-mix! key state)
  (kaesar--sub-bytes! state)
  (kaesar--shift-rows! state)
  (kaesar--add-round-key!
   state (kaesar--round-key key (* kaesar--Nr kaesar--Nb)))
  state)

(defsubst kaesar--inv-shift-sub-mix! (state key)
  (loop for round downfrom (1- kaesar--Nr) to 1
        do (let ((part-key (kaesar--round-key key (* round kaesar--Nb))))
             ;; FIXME: first row only inv-S-box
             (kaesar--sub/shift-box! state 0 '(0 1 2 3) kaesar--inv-S-box)
             (kaesar--sub/shift-box! state 1 '(3 0 1 2) kaesar--inv-S-box)
             (kaesar--sub/shift-box! state 2 '(2 3 0 1) kaesar--inv-S-box)
             (kaesar--sub/shift-box! state 3 '(1 2 3 0) kaesar--inv-S-box)
             (kaesar--inv-key-with-mix-columns! part-key state))))

(defsubst kaesar--inv-cipher (state key)
  (kaesar--add-round-key!
   state (kaesar--round-key key (* kaesar--Nr kaesar--Nb)))
  (kaesar--inv-shift-sub-mix! state key)
  (kaesar--inv-shift-rows! state)
  (kaesar--inv-sub-bytes! state)
  (kaesar--add-round-key! state (kaesar--round-key key 0))
  state)

;;
;; Block mode Algorithm
;;

(defsubst kaesar--cbc-state-xor! (state0 state-1)
  (loop for w1 across state-1
        for w2 across state0
        do (kaesar--word-xor! w2 w1)
        finally return state0))

(defun kaesar--cbc-encrypt (unibyte-string key iv)
  (loop with pos = 0
        with state-1 = (kaesar--unibytes-to-state iv)
        append (let* ((parsed (kaesar--read-unibytes unibyte-string pos))
                      (state-d0 (kaesar--cbc-state-xor! (nth 0 parsed) state-1))
                      (state-e0 (kaesar--cipher state-d0 key)))
                 (setq pos (nth 1 parsed))
                 (setq state-1 state-e0)
                 (kaesar--state-to-bytes state-e0))
        while pos))

(defun kaesar--cbc-decrypt (encbyte-string key iv)
  (kaesar--check-encbyte-string encbyte-string)
  (loop with pos = 0
        with state-1 = (kaesar--unibytes-to-state iv)
        append (let* ((parsed (kaesar--read-encbytes encbyte-string pos))
                      (state-e (nth 0 parsed))
                      ;; Clone state cause of `kaesar--inv-cipher' have side-effect
                      (state-e0 (kaesar--state-clone state-e))
                      (state-d0 (kaesar--cbc-state-xor!
                                 (kaesar--inv-cipher state-e key) state-1))
                      (bytes (kaesar--state-to-bytes state-d0)))
                 (setq pos (nth 1 parsed))
                 (setq state-1 state-e0)
                 (unless pos
                   (setq bytes (kaesar--check-end-of-decrypted bytes)))
                 (append bytes nil))
        while pos))

(put 'kaesar-decryption-failed
     'error-conditions '(kaesar-decryption-failed error))
(put 'kaesar-decryption-failed
     'error-message "Bad decrypt")

;; check End-Of-Block bytes
(defun kaesar--check-end-of-decrypted (eob-bytes)
  (let* ((pad (car (last eob-bytes)))
         (valid-len (- kaesar--Block pad)))
    (when (or (> valid-len (length eob-bytes))
              (< valid-len 0))
      (signal 'kaesar-decryption-failed nil))
    ;; check non padding byte exists
    ;; o aaa => '(97 97 97 13 13 .... 13)
    ;; x aaa => '(97 97 97 13 10 .... 13)
    (when (remove pad (nthcdr valid-len eob-bytes))
      (signal 'kaesar-decryption-failed nil))
    (loop for i from 0 below valid-len
          for u in eob-bytes
          collect u)))

(defun kaesar--check-encbyte-string (string)
  (unless (= (mod (length string) kaesar--Block) 0)
    (signal 'kaesar-decryption-failed nil)))

(defun kaesar--ecb-encrypt (unibyte-string key &rest dummy)
  (loop with pos = 0
        append (let* ((parse (kaesar--read-unibytes unibyte-string pos))
                      (in-state (nth 0 parse))
                      (out-state (kaesar--cipher in-state key)))
                 (setq pos (nth 1 parse))
                 (kaesar--state-to-bytes out-state))
        while pos))

(defun kaesar--ecb-decrypt (encbyte-string key &rest dummy)
  (kaesar--check-encbyte-string encbyte-string)
  (loop with pos = 0
        append (let* ((parse (kaesar--read-encbytes encbyte-string pos))
                      (in-state (nth 0 parse))
                      (out-state (kaesar--inv-cipher in-state key))
                      (bytes (kaesar--state-to-bytes out-state)))
                 (setq pos (nth 1 parse))
                 (unless pos
                   (setq bytes (kaesar--check-end-of-decrypted bytes)))
                 (append bytes nil))
        while pos))

;;;
;;; User level API
;;;

;;;###autoload
(defun kaesar-encrypt-string (string)
  "Encrypt a well encoded STRING to encrypted string
which can be decrypted by `kaesar-decrypt-string'."
  (let ((unibytes (encode-coding-string string default-terminal-coding-system)))
    (kaesar-encrypt unibytes)))

;;;###autoload
(defun kaesar-decrypt-string (encrypted-string)
  "Decrypt a ENCRYPTED-STRING which was encrypted by `kaesar-encrypt-string'"
  (let ((unibytes (kaesar-decrypt encrypted-string)))
    (decode-coding-string unibytes default-terminal-coding-system)))

;;;###autoload
(defun kaesar-encrypt (unibyte-string &optional algorithm)
  "Encrypt a UNIBYTE-STRING with ALGORITHM.
See `kaesar-algorithm' list the supported ALGORITHM ."
  (kaesar--check-unibytes unibyte-string)
  (let* ((salt (kaesar--create-salt))
         (pass (kaesar--read-passwd
                (or kaesar-encrypt-prompt
                    "Password to encrypt: ") t)))
    (kaesar--proc algorithm
      (destructuring-bind (raw-key iv) (kaesar--bytes-to-key pass salt)
        (kaesar--encrypt-0 unibyte-string raw-key salt iv)))))

;;;###autoload
(defun kaesar-decrypt (encrypted-string &optional algorithm)
  "Decrypt a ENCRYPTED-STRING which was encrypted by `kaesar-encrypt'"
  (kaesar--check-encrypted encrypted-string)
  (let ((algorithm (or algorithm
                       (get-text-property 0 'encrypted-algorithm encrypted-string))))
    (kaesar--proc algorithm
      (destructuring-bind (salt encrypted-string)
          (kaesar--parse-salt encrypted-string)
        (let ((pass (kaesar--read-passwd
                     (or kaesar-decrypt-prompt
                         "Password to decrypt: "))))
          (destructuring-bind (raw-key iv) (kaesar--bytes-to-key pass salt)
            (kaesar--decrypt-0 encrypted-string raw-key iv)))))))

;;;###autoload
(defun kaesar-encrypt-by-key (unibyte-string algorithm raw-key &optional iv)
  "Encrypt a UNIBYTE-STRING with ALGORITHM and RAW-KEY (Before expansion).
See `kaesar-algorithm' list the supported ALGORITHM .
Low level API to encrypt like other implementation."
  (kaesar--check-unibytes unibyte-string)
  (kaesar--proc algorithm
    ;;TODO check raw-key length?
    (let* ((key (kaesar--key-expansion raw-key))
           (encrypted (funcall kaesar--Enc unibyte-string key iv))
           (full-data (append encrypted)))
      (apply 'kaesar--unibyte-string full-data))))

;;;###autoload
(defun kaesar-decrypt-by-key (encrypted-string algorithm raw-key &optional iv)
  "Decrypt a ENCRYPTED-STRING which was encrypted by `kaesar-encrypt' with RAW-KEY.
RAW-KEY before expansion
Low level API to decrypt data that was encrypted by other implementation."
  (kaesar--check-encrypted encrypted-string)
  (kaesar--proc algorithm
    ;;TODO check raw-key length?
    (let* ((key (kaesar--key-expansion raw-key))
           (decrypted (funcall kaesar--Dec encrypted-string key iv)))
      (apply 'kaesar--unibyte-string decrypted))))

(provide 'kaesar)

;;; kaesar.el ends here
