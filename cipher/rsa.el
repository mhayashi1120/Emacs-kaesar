;;; cipher/aes.el --- Encrypt/Decrypt string with password.

;; Author: Masahiro Hayashi <mhayashi1120@gmail.com>
;; Keywords: encrypt decrypt password
;; URL: http://github.com/mhayashi1120/Emacs-aes/raw/master/aes.el
;; Emacs: GNU Emacs 22 or later
;; Version 0.0.1

(defconst cipher/rsa-version "0.0.1")

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

;;; Sample:

;; * To encrypt our secret
;;   Please ensure that do not forget `clear-string' you want to hide.

;; (defvar our-secret nil)

;; (let ((raw-string "Our Secret"))
;;   (setq our-secret (cipher/rsa-encrypt-string raw-string))
;;   (clear-string raw-string))

;; * To decrypt `our-secret'

;; (cipher/rsa-decrypt-string our-secret)

;;; TODO:

;; * encrypt/decrypt our secret
;; * generate key pair
;; * sign/check

;;; Code:

(eval-when-compile
  (require 'cl))

(require 'bignum)
 
;;;
;;; Interfaces
;;;

;;;###autoload
(defun cipher/rsa-encrypt-string (his-public-key string &optional coding-system)
  "Encrypt a well encoded STRING with HIS-PUBLIC-KEY to encrypted object 
which can be decrypted by `cipher/rsa-decrypt-string'."
  (let* ((cs (or coding-system default-terminal-coding-system))
         (M (encode-coding-string string cs)))
    (cipher/rsa--encrypt-bytes M his-public-key)))

;;;###autoload
(defun cipher/rsa-decrypt-string (my-private-key encrypted-string &optional coding-system)
  "Decrypt a ENCRYPTED-STRING with MY-PRIVATE-KEY which was encrypted
by `cipher/aes-encrypt-string'"
  (let ((M (cipher/rsa--decrypt-bytes encrypted-string my-private-key))
        (cs (or coding-system default-terminal-coding-system)))
    (decode-coding-string M cs)))

;;;###autoload
(defun cipher/rsa-sign-string (my-private-key hash)
  "Sign HASH with MY-PRIVATE-KEY. 
Returned value will be verified with `cipher/rsa-verify-string'
with my-public-key. "
  (let* ((M hash)
         (sign (cipher/rsa--sign-bytes M my-private-key)))
    (base64-encode-string sign t)))

;;;###autoload
(defun cipher/rsa-verify-string (his-public-key sign hash)
  "Verify SIGN which created with `cipher/rsa-sign-string' by private-key.
Decrypted string must equal HASH otherwise raise error.
"
  (let* ((C (base64-decode-string sign))
         (verify (cipher/rsa--verify-bytes C his-public-key)))
    (unless (string= verify hash)
      (error "Failed while verifying"))
    t))

;;;
;;; inner functions
;;;

(defun cipher/rsa--encrypt-bytes (M key &optional block-size)
  (cipher/rsa--encode-bytes 
   M (cipher/rsa-key:E key) key block-size))

(defun cipher/rsa--sign-bytes (M key &optional block-size)
  (cipher/rsa--encode-bytes 
   M (cipher/rsa-key:D key) key block-size))

(defun cipher/rsa--encode-bytes (M e key &optional block-size)
  (when (> (length M) 255)
    (error "Exceed limit"))
  (let* ((n (cipher/rsa-key:N key))
         (size (or block-size
                   (cipher/rsa-key-size key))))
    (loop for c across M
          concat (let ((C (cipher/rsa--encrypt-char c e n)))
                   (bignum-serialize C size)))))

(defun cipher/rsa--decrypt-bytes (C key &optional block-size)
  (cipher/rsa--decode-bytes
   C (cipher/rsa-key:D key) key block-size))

(defun cipher/rsa--verify-bytes (C key &optional block-size)
  (cipher/rsa--decode-bytes
   C (cipher/rsa-key:E key) key block-size))

(defun cipher/rsa--decode-bytes (C d key &optional block-size)
  (let ((n (cipher/rsa-key:N key))
        (size (or block-size
                  (cipher/rsa-key-size key)))
        (lC (append C nil)))
    (loop for (bC rest) = (bignum-read-bytes lC size) 
          then (and rest (bignum-read-bytes rest size))
          while bC
          collect (cipher/rsa--decrypt-char bC d n)
          into res
          finally return (apply 'cipher/rsa--unibyte-string res))))

(defun cipher/rsa--encrypt-char (M be n)
  (let* ((M2 (+ M 2))
         (bM2 (bignum M2))
         (bC (bignum-modulo-product n bM2 be)))
    bC))

(defun cipher/rsa--decrypt-char (bC d n)
  (let* ((bM (bignum-modulo-product n bC d))
         (M (bignum-to-number bM)))
    (- M 2)))

;;;
;;; Handling key
;;;

(defun cipher/rsa-key-size (key)
  (loop with n = (cipher/rsa-key:N key)
        until (bignum-zerop n)
        for i from 0
        do (setq n (bignum-rshift n 1))
        finally return (+ (/ i 8)
                          (if (zerop (% i 8)) 0 1))))

(defun cipher/rsa-generate-key (name bits)
  ;;TODO
  (let* ((p (bignum-random-prime (/ bits 2)))
         (q (bignum-random-prime (/ bits 2)))
         (n (bignum-mul p q))
         (L (bignum-lcm (bignum-1- p) (bignum-1- q)))
         (e (bignum 11))                ;TODO 4th felmar 65537
         (d (cdr (cipher/rsa-euclid L e))))
    (when (bignum= d (bignum-one))
      (setq e (bignum 65537))
      (setq d (cdr (cipher/rsa-euclid L e))))
    ;;TODO
    (cipher/rsa-key:make name n e d)))

(defun cipher/rsa-key:export-public (key)
  (cipher/rsa-key:make 
   (cipher/rsa-key:ID key)
   (cipher/rsa-key:N key)
   (cipher/rsa-key:E key)
   nil))

(defun cipher/rsa-key:secret-p (key)
  (cipher/rsa-key:D key))

(defun cipher/rsa-key:make (id n e d)
  (list id n e d))

(defun cipher/rsa-key:ID (key)
  (nth 0 key))

(defun cipher/rsa-key:N (key)
  (nth 1 key))

(defun cipher/rsa-key:E (key)
  (nth 2 key))

(defun cipher/rsa-key:D (key)
  (nth 3 key))

;;
;; Openssh key manipulation
;;

(defun cipher/rsa-openssh-load-key (file)
  (with-temp-buffer
    (insert-file-contents file)
    (cipher/rsa-openssh-key (buffer-string))))

(defun cipher/rsa-openssh-load-pubkey (pub-file)
  (with-temp-buffer
    (insert-file-contents pub-file)
    (cipher/rsa-openssh-pubkey (buffer-string))))

(defun cipher/rsa-openssh-pubkey (pub-line)
  (unless (string-match "^ssh-rsa \\([a-zA-Z0-9+/]+=*\\)\\(?: \\(.*\\)\\)?" pub-line)
    (error "Not a rsa public key line"))
  (let* ((key (match-string 1 pub-line))
         (comment (match-string 2 pub-line))
         (binary (append (base64-decode-string key) nil))
         (blocks (cipher/rsa--read-sequence-blocks binary)))
    (destructuring-bind (type e n) blocks
      (let* ((tobn (lambda (bs)
                     (bignum-from-string
                      (mapconcat (lambda (x) (format "%02x" x)) bs "")
                      16)))
             ;; ignore sign byte by `cdr'
             (N (funcall tobn (cdr n)))
             (E (funcall tobn e)))
        (list comment N E)))))

(defun cipher/rsa--read-sequence-blocks (string)
  (let ((bytes (append string nil))     ; todo encoding
        res tmp len data)
    (while bytes
      (setq tmp (bignum-read-int32 bytes))
      (setq len (bignum-to-number (car tmp))
            bytes (cadr tmp))
      (loop for bs on bytes
            repeat len
            collect (car bs) into res
            finally (setq data res
                          bytes bs))
      (setq res (cons data res)))
    (nreverse res)))

;;;
;;; Arithmetic calculation
;;;

(defun cipher/rsa-euclid (bignum1 bignum2)
  (if (bignum> bignum1 bignum2)
      (cipher/rsa-euclid-0 bignum1 bignum2)
    (cipher/rsa-euclid-0 bignum2 bignum1)))

;; http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
(defun cipher/rsa-euclid-0 (bignum1 bignum2)
  (loop with a = bignum1
        with b = bignum2
        with x = (bignum-zero)
        with y = (bignum-one)
        with x-1 = (bignum-one)
        with y-1 = (bignum-zero)
        with tmp
        until (bignum-zerop b)
        do (let* ((q&r (bignum-div&rem a b))
                  (q (car q&r))
                  (r (cdr q&r)))
             (setq a b)
             (setq b r)
             (setq tmp x)
             (setq x (bignum-add x-1 (bignum-mul q x)))
             (setq x-1 tmp)
             (setq tmp y)
             (setq y (bignum-add y-1 (bignum-mul q y)))
             (setq y-1 tmp))
        finally return 
        (let ((tmp-x (bignum-mul bignum1 x-1))
              (tmp-y (bignum-mul bignum2 y-1)))
          (if (bignum< tmp-x tmp-y)
              (cons x-1 y-1)
            ;; make y coefficient to plus value
            (cons (bignum-diff bignum2 x-1)
                  (bignum-diff bignum1 y-1))))))

;;TODO
(defun cipher/rsa--sub (snum1 snum2)
  (destructuring-bind (sign1 bignum1) snum1
    (destructuring-bind (sign2 bignum2) snum2
      (cond
       ((eq sign1 sign2)
        (list (if (bignum> bignum1 bignum2) sign1 sign2)
              (bignum-diff bignum1 bignum2)))
       (t
        (list sign1 (bignum-add bignum1 bignum2)))))))

(if (fboundp 'unibyte-string)
    (defalias 'cipher/rsa--unibyte-string 'unibyte-string)
  (defun cipher/rsa--unibyte-string (&rest bytes)
    (concat bytes)))

(defun cipher/rsa--read-bytes (bytes pos len)
  (loop with res = (bignum (aref bytes pos))
        with max-len = (length bytes)
        for i from (1+ pos) below (min (+ pos len) max-len)
        do (setq res (bignum-logior (bignum-lshift res 8) (bignum (aref bytes i))))
        finally return (cons res (if (= i max-len) nil i))))



(provide 'cipher/rsa)

;;; cipher/rsa.el ends here
