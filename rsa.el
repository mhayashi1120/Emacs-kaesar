;;; rsa.el --- Encrypt/Decrypt string with RSA key.

;; Author: Masahiro Hayashi <mhayashi1120@gmail.com>
;; Keywords: data
;; URL: http://github.com/mhayashi1120/Emacs-cipher/raw/master/rsa.el
;; Emacs: GNU Emacs 22 or later
;; Version: 0.0.2
;; Package-Requires: ()

(defconst rsa-version "0.0.2")

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

;; Put this file into load-path'ed with "cipher" directory, and
;; !!!!!!!!!!!!!!! BYTE COMPILE IT !!!!!!!!!!!!!!!
;; And put the following expression into your .emacs.
;;
;;     (require 'rsa)

;;; Usage:

;;; Sample:

;; * To encrypt our secret
;;   Please ensure that do not forget `clear-string' you want to hide.

;;TODO load public key from openssh
;; (defvar our-secret nil)

;; (let ((raw-string "Our Secret")
;;       (key (rsa-openssh-load-publine public-key-in-authorized_keys-file)))
;;   (setq our-secret (rsa-encrypt-string key raw-string))
;;   (clear-string raw-string))

;; * To decrypt `our-secret'

;;TODO load private key from openssh
;; (rsa-decrypt-string our-secret)

;;; TODO:

;; * generate key pair
;; * load openssh secret key
;; * ASN1 PEM technical term is correct?

;;; Code:

(eval-when-compile
  (require 'cl))

(defgroup rsa nil
  "Encrypt/Decrypt, Sign/Verify string with rsa key"
  :group 'environment)

(require 'calc)
(require 'calc-ext)
(require 'calc-bin)

(defcustom rsa-padding-method 'pkcs
  "Padding method to use."
  :group 'rsa
  :type '(choice
          (const pkcs)
          (const sslv23)
          (const oaep)))

;;;
;;; Interfaces
;;;

;;;###autoload
(defun rsa-encrypt-string (his-public-key string &optional coding-system)
  "Encrypt a well encoded STRING with HIS-PUBLIC-KEY to encrypted object
which can be decrypted by `rsa-decrypt-string'."
  (let* ((cs (or coding-system default-terminal-coding-system))
         (M (encode-coding-string string cs)))
    (rsa--encode-bytes M his-public-key nil)))

;;;###autoload
(defun rsa-decrypt-string (my-private-key encrypted-string &optional coding-system)
  "Decrypt a ENCRYPTED-STRING with MY-PRIVATE-KEY which was encrypted
by `rsa-encrypt-string'"
  (let ((M (rsa--decode-bytes encrypted-string my-private-key nil))
        (cs (or coding-system default-terminal-coding-system)))
    (decode-coding-string M cs)))

;;;###autoload
(defun rsa-encrypt-bytes (his-public-key string)
  "Encrypt a well encoded STRING with HIS-PUBLIC-KEY to encrypted object
which can be decrypted by `rsa-decrypt-string'."
  (rsa--check-unibyte-string string)
  (rsa--encode-bytes string his-public-key nil))

;;;###autoload
(defun rsa-decrypt-bytes (my-private-key encrypted-string)
  "Decrypt a ENCRYPTED-STRING with MY-PRIVATE-KEY which was encrypted
by `rsa-encrypt-bytes'"
  (rsa--check-unibyte-string encrypted-string)
  (rsa--decode-bytes encrypted-string my-private-key nil))

;;;###autoload
(defun rsa-sign-hash (my-private-key digest)
  "Sign DIGEST with MY-PRIVATE-KEY.
Returned value will be verified by `rsa-verify-hash'
with MY-PUBLIC-KEY. "
  (rsa--check-unibyte-string digest)
  (let* ((M digest)
         (sign (rsa--encode-bytes M my-private-key t)))
    sign))

;;;###autoload
(defun rsa-verify-hash (his-public-key sign digest)
  "Verify SIGN which created by `rsa-sign-hash' with private-key.
Decrypted unibyte string must equal DIGEST otherwise raise error.
"
  (rsa--check-unibyte-string digest)
  (let* ((verify (rsa--decode-bytes sign his-public-key t)))
    (unless (equal verify digest)
      (error "Sign must be `%s' but `%s'" digest verify))
    t))

;;;
;;; inner functions
;;;

(put 'rsa-decryption-failed
     'error-conditions '(rsa-decryption-failed error))
(put 'rsa-decryption-failed
     'error-message "Decoding error")

(put 'rsa-encryption-failed
     'error-conditions '(rsa-encryption-failed error))
(put 'rsa-encryption-failed
     'error-message "Encoding error")

(defun rsa--check-unibyte-string (s)
  (when (multibyte-string-p s)
    (error "Not a unibyte string `%s'" s)))

(defun rsa--bn-to-text (bn)
  (loop for (d . r) = (rsa-bn:div&rem bn 256)
        then (rsa-bn:div&rem d 256)
        collect r into res
        until (rsa-bn:zerop d)
        finally return (apply 'rsa--unibytes (nreverse res))))

(defun rsa--hex-to-bytes (hex)
  (loop with len = (length hex)
        for i from 0 below len by 2
        for j from (if (zerop (% len 2)) 2 1) by 2
        collect (string-to-number (substring hex i j) 16)))

(defun rsa--encode-bytes (text key sign-p)
  (let* ((n (rsa-key:N key))
         (e (if sign-p
                (rsa-key:D key)
              (rsa-key:E key)))
         (size (rsa-key-size key))
         ;;TODO difference between sign and encrypt
         (padded (rsa--padding-add text size))
         (M (rsa-bn:from-bytes padded))
         (C (rsa-bn:modulo-product n M e))
         (encrypt (rsa-bn:serialize C size)))
    encrypt))

(defun rsa--decode-bytes (encrypt key verify-p)
  (let ((n (rsa-key:N key))
        (size (rsa-key-size key)))
    (unless (= (length encrypt) size)
      (signal 'rsa-decryption-failed
              (list (format "Illegal length(%d) of encrypted text (%s)"
                            size encrypt))))
    (let* ((d (if verify-p
                  (rsa-key:E key)
                (rsa-key:D key)))
           (C (rsa-bn:from-bytes encrypt))
           (M (rsa-bn:modulo-product n C d))
           (padded (rsa-bn:serialize M size))
           (text (rsa--padding-remove padded)))
      text)))

;;;
;;; RSA padding algorithm
;;;

(defun rsa--random-memset (vec start len)
  (loop repeat len
        for i from start
        do (progn
             (aset vec i (let (r)
                           (while (zerop (setq r (random 256))))
                           r)))
        finally return i))

(defun rsa--xor-masking (data mask)
  (loop for m in mask
        for d in data
        for i from 0
        collect (logxor d m)))

(defun rsa--padding-sslv23-add (text size)
  (let ((len (length text))
        (allow-len (- size (+ 2 8 1))))
    (when (> len allow-len)
      (signal 'rsa-encryption-failed
              (list (format "Exceed limit (Must be smaller than %d but %d)"
                            allow-len len))))
    (let* ((suffix (make-list (- size len) 0))
           (origin (string-to-list text))
           (nulllen (- (length suffix) 3 8))
           (full (append suffix origin))
           (vec (apply 'rsa--unibytes full))
           (i 0))
      (aset vec 0 0)
      (aset vec 1 2)                    ; Public Key BT (Block Type)
      (setq i (rsa--random-memset vec 2 nulllen))
      (loop repeat 8
            do (progn
                 (aset vec i 3)
                 (setq i (1+ i))))
      (aset vec i 0)
      vec)))

(defun rsa--padding-sslv23-remove (text)
  (unless (= (aref text 0) 0)
    (signal 'rsa-encryption-failed
            (list "Expected null byte")))
  (loop for i from 1 below (length text)
        if (zerop (aref text i))
        return (substring text (1+ i))))

(defun rsa--padding-pkcs-add-1 (block-type text size filler)
  (let ((len (length text))
        (allow-len (- size (+ 2 8 1))))
    (when (> len allow-len)
      (signal 'rsa-encryption-failed
              (list (format "Exceed limit (Must be smaller than %d but %d)"
                            allow-len len))))
    (let* ((suffix (make-list (- size (length text)) 0))
           (origin (string-to-list text))
           (fill-len (- (length suffix) 3))
           (full (append suffix origin))
           (vec (apply 'rsa--unibytes full))
           (i 0))
      (aset vec 0 0)
      (aset vec 1 block-type)
      (setq i (funcall filler vec 2 fill-len))
      (aset vec i 0)
      vec)))

(defun rsa--padding-pkcs-add (text size)
  ;; 2: Public Key BT (Block Type)
  (rsa--padding-pkcs-add-1
   2 text size 'rsa--random-memset))

;;TODO not tested openssl 0.9.8 not yet supported?
(defun rsa--padding-pkcs-add2 (text size)
  ;; 1: Private Key BT (Block Type)
  (rsa--padding-pkcs-add-1
   1 text size
   (lambda (vec start len)
     (rsa--vecset vec start ?\xff len))))

(defun rsa--padding-pkcs-remove (text)
  (unless (= (aref text 0) 0)
    (signal 'rsa-encryption-failed
            (list "Expected null byte")))
  (loop for i from 1 below (length text)
        if (zerop (aref text i))
        return (substring text (1+ i))))

(defun rsa--padding-oaep-add (text size)
  (let* ((from (string-to-list text))
         (vhash (rsa--hex-to-bytes (sha1 "")))
         (sha1-len (length vhash))
         (max-len (- size 1 sha1-len sha1-len 1)))
    (when (minusp max-len)
      (signal 'rsa-encryption-failed
              (list "Key size too small")))
    (when (> (length text) max-len)
      (signal 'rsa-encryption-failed
              (list "Text exceed key size limit")))
    ;; before MGF
    ;; 0x00 (1)
    ;; seed (20) random
    ;; db (20 < db to rest of keysize)
    ;;   db_seed(20) (sha1 "")
    ;;   0pad
    ;;   0x01(1)
    ;;   data(input data length)
    (let ((seed (make-list sha1-len 0))
          (db (make-list (- size sha1-len) 0)))

      ;; set db
      (loop for b in vhash
            for i from 0
            do (rsa--listset db i b))
      (rsa--listcpy (last db (+ 1 (length from))) (cons 1 from))
      ;; set seed
      (loop repeat sha1-len
            for i from 0
            do (rsa--listset seed i (random 256)))

      ;; XOR masking
      (let* ((dbmask (rsa--oaep-MGF seed (length db)))
             (maskeddb (rsa--xor-masking db dbmask))
             (seedmask (rsa--oaep-MGF maskeddb (length seed)))
             (maskedseed (rsa--xor-masking seed seedmask)))
        (cons 0 (append maskedseed maskeddb))))))

(defun rsa--padding-oaep-remove (text)
  ;; ignore Side-Channel attack.
  ;; No need to concern about it in elisp.
  (let* ((from (string-to-list text))
         (taker (lambda (n l)
                  (loop repeat n
                        for x in l
                        collect x)))
         ;; to verify hash
         (vhash (rsa--hex-to-bytes (sha1 "")))
         (sha1-len (length vhash))
         (maskedseed (funcall taker sha1-len (nthcdr 1 from)))
         (maskeddb (copy-sequence (nthcdr (+ 1 sha1-len) from)))
         ;; XOR unmasking
         (seedmask (rsa--oaep-MGF maskeddb sha1-len))
         (seed (rsa--xor-masking seedmask maskedseed))
         (dbmask (rsa--oaep-MGF seed (length maskeddb)))
         (db (rsa--xor-masking dbmask maskeddb))
         (hash (funcall taker sha1-len db)))
    (unless (equal vhash hash)
      (signal 'rsa-decryption-failed (list "Hash is changed")))
    (loop for xs on (nthcdr sha1-len db)
          while (zerop (car xs))
          finally return
          (let ((data (cdr xs)))
            (unless (= (car xs) 1)
              (signal 'rsa-decryption-failed (list "No digit")))
            (apply 'rsa--unibytes data)))))

(defun rsa--oaep-MGF (seed require-len)
  (loop for i from 0
        while (< (length out) require-len)
        append
        (let* ((cnt (list
                     (logand (lsh i -24) ?\xff)
                     (logand (lsh i -16) ?\xff)
                     (logand (lsh i  -8) ?\xff)
                     (logand      i      ?\xff)))
               (bytes (apply 'rsa--unibytes (append seed cnt))))
          (rsa--hex-to-bytes (sha1 bytes)))
        into out
        finally return (loop repeat require-len
                             for b in out
                             collect b)))

(defun rsa--padding-add (text size)
  (let ((func (intern-soft
               (format "rsa--padding-%s-add"
                       rsa-padding-method))))
    (cond
     ((fboundp func)
      (funcall func text size)
      ;; (rsa--padding-pkcs-add2 text size)
      )
     (t
      (error "Not supported type %s"
             rsa-padding-method)))))

(defun rsa--padding-remove (text)
  (let ((func (intern-soft
               (format "rsa--padding-%s-remove"
                       rsa-padding-method))))
    (cond
     ((fboundp func)
      (funcall func text))
     (t
      (error "Not supported type %s"
             rsa-padding-method)))))

;;;
;;; Handling key
;;;

(defun rsa-key-size (key)
  (loop with n = (rsa-key:N key)
        until (rsa-bn:zerop n)
        for i from 0
        do (setq n (rsa-bn:rshift n 1))
        finally return (+ (/ i 8)
                          (if (zerop (% i 8)) 0 1))))

(defun rsa-generate-key (bits &optional comment)
  ;;TODO
  (let* ((p (rsa-bn:random-prime (/ bits 2)))
         (q (rsa-bn:random-prime (/ bits 2)))
         (n (rsa-bn:* p q))
         (L (rsa-bn:lcm
             (rsa-bn:1- p) (rsa-bn:1- q)))
         (e 11)                ;TODO 4th felmar 65537
         (d (cdr (rsa-euclid L e))))
    (when (rsa-bn:= d 1)
      (setq e 65537)
      (setq d (cdr (rsa-euclid L e))))
    ;;TODO
    (rsa-key:make comment n e d)))

(defun rsa-key:export-public (key)
  (rsa-key:make
   (rsa-key:comment key)
   (rsa-key:N key)
   (rsa-key:E key)
   nil))

(defun rsa-key:secret-p (key)
  (and (rsa-key:D key) t))

(defun rsa-key:make (comment n e d)
  (list comment n e d))

(defun rsa-key:comment (key)
  (nth 0 key))

(defun rsa-key:N (key)
  (nth 1 key))

(defun rsa-key:E (key)
  (nth 2 key))

(defun rsa-key:D (key)
  (nth 3 key))

;;
;; Openssh key manipulation
;;

(defun rsa--insert-file-as-binary (file)
  (set-buffer-multibyte nil)
  (let ((coding-system-for-read 'binary))
    (insert-file-contents file)))

(defun rsa-openssh-load-key (file)
  (with-temp-buffer
    (rsa--insert-file-as-binary file)
    ;; Decode openssh or openssl secret key file.
    (rsa--openssh-decrypt-maybe file)
    (let* ((data (string-to-list (buffer-string)))
           (blocks (rsa--asn1-read-blocks data)))
      ;; ASN1_SEQUENCE_cb(RSAPrivateKey, rsa_cb) = {
      ;;  ASN1_SIMPLE(RSA, version, LONG),
      ;;  ASN1_SIMPLE(RSA, n, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, e, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, d, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, p, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, q, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, dmp1, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, dmq1, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, iqmp, BIGNUM)
      ;; } ASN1_SEQUENCE_END_cb(RSA, RSAPrivateKey)
      (rsa-key:make
       nil
       (rsa-bn:from-bytes (nth 1 blocks))
       (rsa-bn:from-bytes (nth 2 blocks))
       (rsa-bn:from-bytes (nth 3 blocks))))))

(defun rsa--asn1-read-blocks (data)
  (destructuring-bind (tag seqlen seq)
      (rsa--asn1-read-object data)
    ;;TODO check tag?
    ;; (unless (= tag ?\x30)
    ;;   (error "TODO"))
    (unless (= seqlen (length seq))
      (signal 'invalid-read-syntax (list "Unexpected bytes")))
    (loop with list = seq
          while list
          collect (destructuring-bind (tag len rest)
                      (rsa--asn1-read-object list)
                    (loop repeat len
                          for xs on rest
                          collect (car xs)
                          finally (setq list xs))))))

;; '(inf ret rest)
(defun rsa--asn1-read-length (list)
  (let ((i (logand (car list) ?\x7f)))
    (cond
     ((= (car list) ?\x80)
      (list 1 (cdr list)))
     ((plusp (logand (car list) ?\x80))
      (setq list (cdr list))
      (when (> i 3) (error "Too huge data %d" i))
      (loop with ret = 0
            for j downfrom i above 0
            for xs on list
            do (progn
                 (setq ret (lsh ret 8))
                 (setq ret (logior ret (car xs))))
            finally return (list ret xs)))
     (t
      (list i (cdr list))))))

(defun rsa--asn1-read-object (list)
  (let* ((V_ASN1_PRIMITIVE_TAG  ?\x1f)
         (i (logand (car list) V_ASN1_PRIMITIVE_TAG))
         tag)
    (cond
     ((= i V_ASN1_PRIMITIVE_TAG)
      (error "TODO Not yet tested")
      (setq list (cdr list))
      (loop with l = 0
            for xs on list
            do (progn
                 (setq l (lsh l 7))
                 (setq l (logand (car xs) ?\x7f)))
            ;;todo
            ;; if (l > (INT_MAX >> 7L)) goto err;
            while (plusp (logand (car xs) ?\x80))
            finally (setq tag l)))
     (t
      (setq tag i)
      (setq list (cdr list))))
    ;;TODO tag is not used
    (destructuring-bind (len rest) (rsa--asn1-read-length list)
      (list tag len rest))))

(defun rsa-openssh-load-pubkey (pub-file)
  (with-temp-buffer
    (rsa--insert-file-as-binary pub-file)
    (goto-char (point-min))
    (cond
     ((looking-at "^ssh-rsa ")
      (rsa-openssh-load-publine (buffer-string)))
     ((looking-at "^-----BEGIN PUBLIC KEY-----")
      (rsa--read-openssl-pubkey))
     (t
      (error "Unrecognized format %s" pub-file)))))

(defun rsa--read-openssl-pubkey ()
  (unless (re-search-forward "^-----BEGIN PUBLIC KEY-----" nil t)
    (signal 'invalid-read-syntax (list "No public key header")))
  (let ((start (point)))
    (unless (re-search-forward "^-----END PUBLIC KEY-----" nil t)
      (signal 'invalid-read-syntax (list "No public key footer")))
    (let* ((end (match-beginning 0))
           (str (buffer-substring start end))
           (raw (base64-decode-string str))
           (data (string-to-list raw))
           (top-blocks (rsa--asn1-read-blocks data))
           ;; public key have recursive structure.
           (bit-string (nth 1 top-blocks))
           (blocks (rsa--asn1-read-blocks
                    (loop for xs on bit-string
                          unless (zerop (car xs))
                          return xs))))
      ;; ASN1_SEQUENCE_cb(RSAPublicKey, rsa_cb) = {
      ;;        ASN1_SIMPLE(RSA, n, BIGNUM),
      ;;        ASN1_SIMPLE(RSA, e, BIGNUM),
      ;; } ASN1_SEQUENCE_END_cb(RSA, RSAPublicKey)
      (rsa-key:make
       nil
       (rsa-bn:from-bytes (nth 0 blocks))
       (rsa-bn:from-bytes (nth 1 blocks))
       nil))))

(defconst rsa--re-openssh-publine
  (concat
   "\\`"
   "ssh-rsa "
   "\\([a-zA-Z0-9+/]+=*\\)"
   "\\(?: \\(.*\\)\\)?"))

(defun rsa-openssh-load-publine (pub-line)
  (unless (string-match rsa--re-openssh-publine pub-line)
    (error "Not a rsa public key line"))
  (let* ((key (match-string 1 pub-line))
         (comment (match-string 2 pub-line))
         (binary (append (base64-decode-string key) nil))
         (blocks (rsa--read-publine-blocks binary)))
    (destructuring-bind (type e n) blocks
      (let (
            ;; ignore sign byte by `cdr'
            (N (rsa-bn:from-bytes (cdr n))) 
            (E (rsa-bn:from-bytes e)))
        (list comment N E)))))

(defun rsa--read-publine-blocks (string)
  (let ((bytes (append string nil))
        data res)
    (while bytes
      (let* ((tmp (rsa-bn:read-int32 bytes))
             (len (rsa-bn:to-number (car tmp))))
        (setq bytes (cadr tmp))
        (loop for bs on bytes
              repeat len
              collect (car bs) into res
              finally (setq data res
                            bytes bs))
        (setq res (cons data res))))
    (nreverse res)))

(declare-function cipher/aes-decrypt-by-key "aes")

(defun rsa--openssh-decrypt-maybe (file)
  (save-excursion
    (goto-char (point-min))
    (unless (re-search-forward "^-----BEGIN RSA PRIVATE KEY-----" nil t)
      (signal 'invalid-read-syntax (list "No base64 data")))
    (let (key algorithm iv)
      (when (and (re-search-forward "^Proc-Type: " nil t)
                 (re-search-forward "^DEK-Info: *\\([^,]+\\),\\(.*\\)" nil t))
        (setq algorithm (downcase (match-string 1)))
        (let* ((hex-iv (match-string 2))
               (prompt (format "Passphrase for (%s): " file))
               (pass (vconcat (read-passwd prompt)))
               (iv-bytes (rsa--hex-to-bytes hex-iv))
               ;; required only 8 bytes to create key
               (iv-8 (loop repeat 8 for b in iv-bytes collect b))
               (A (md5 (apply 'rsa--unibytes (append pass iv-8))))
               (B (md5 (apply
                        'rsa--unibytes
                        (append (rsa--hex-to-bytes A) pass iv-8))))
               (C (md5 (apply
                        'rsa--unibytes
                        (append (rsa--hex-to-bytes B) pass iv-8)))))
          (setq iv (vconcat iv-bytes))
          (setq key (vconcat (rsa--hex-to-bytes (concat A B))))
          (unless (re-search-forward "^$" nil t)
            (signal 'invalid-read-syntax
                    (list "No private key header")))))
      (let ((start (point)))
        (unless (re-search-forward "^-----END RSA PRIVATE KEY-----" nil t)
          (signal 'invalid-read-syntax
                  (list "No private key footer")))
        (forward-line 0)
        (let* ((end (point))
               (b64 (buffer-substring start end))
               data)
          (cond
           (key
            (let ((encrypted (base64-decode-string b64)))
              (require 'cipher/aes)
              (setq data (cipher/aes-decrypt-by-key encrypted algorithm key iv))))
           (t
            (setq data (base64-decode-string b64))))
          (delete-region (point-min) (point-max))
          (set-buffer-multibyte nil)
          (insert data))))))

;; testing 
(defun rsa-openssh-load-key2 (file)
  (require 'asn1)
  (with-temp-buffer
    (rsa--insert-file-as-binary file)
    ;; Decode openssh or openssl secret key file.
    (rsa--openssh-decrypt-maybe file)
    (let* ((asn1 (asn1-parse-buffer))
           (asn1-top (asn1-value (car asn1))))
      ;; ASN1_SEQUENCE_cb(RSAPrivateKey, rsa_cb) = {
      ;;  ASN1_SIMPLE(RSA, version, LONG),
      ;;  ASN1_SIMPLE(RSA, n, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, e, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, d, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, p, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, q, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, dmp1, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, dmq1, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, iqmp, BIGNUM)
      ;; } ASN1_SEQUENCE_END_cb(RSA, RSAPrivateKey)
      (rsa-key:make
       nil
       (rsa-bn:from-bytes (asn1-value (nth 1 asn1-top)))
       (rsa-bn:from-bytes (asn1-value (nth 2 asn1-top)))
       (rsa-bn:from-bytes (asn1-value (nth 3 asn1-top)))))))

;; testing 
(defun rsa--read-openssl-pubkey2 ()
  (require 'asn1)
  (unless (re-search-forward "^-----BEGIN PUBLIC KEY-----" nil t)
    (signal 'invalid-read-syntax (list "No public key header")))
  (let ((start (point)))
    (unless (re-search-forward "^-----END PUBLIC KEY-----" nil t)
      (signal 'invalid-read-syntax (list "No public key footer")))
    (let* ((end (match-beginning 0))
           (str (buffer-substring start end))
           (bytes (base64-decode-string str))
           (asn1 (asn1-parse-string bytes))
           (asn1-top (asn1-value (car asn1))))
      ;; ASN1_SEQUENCE_cb(RSAPublicKey, rsa_cb) = {
      ;;        ASN1_SIMPLE(RSA, n, BIGNUM),
      ;;        ASN1_SIMPLE(RSA, e, BIGNUM),
      ;; } ASN1_SEQUENCE_END_cb(RSA, RSAPublicKey)
      (rsa-key:make
       nil
       (rsa-bn:from-bytes (asn1-value (nth 0 asn1-top)))
       (rsa-bn:from-bytes (asn1-value (nth 1 asn1-top)))
       nil))))

;; openssh-5.9p1/key.c
(defun rsa--openssh-key-to-rawpub (key)
  (let* ((key-type "ssh-rsa")
         (klen (rsa-bn:serialize (length key-type) 4))
         (serializer (lambda (x)
                       (let ((bs (rsa-bn:to-bytes x)))
                         (if (plusp (logand (car bs) ?\x80))
                             (cons 0 bs)
                           bs))))
         (E (rsa-key:E key))
         (e (funcall serializer E))
         (elen (rsa-bn:serialize (length e) 4))
         (N (rsa-key:N key))
         (n (funcall serializer N))
         (nlen (rsa-bn:serialize (length n) 4))
         (raw (append
               (append klen nil)
               (string-to-list key-type)
               (append elen nil)
               e
               (append nlen nil)
               n)))
    (apply 'rsa--unibytes raw)))

(defun rsa-openssh-key-to-publine (key)
  (let ((raw (rsa--openssh-key-to-rawpub key)))
    (format
     "ssh-rsa %s"
     (base64-encode-string raw t))))

(defun rsa-openssh-pubkey-fingerprint (key)
  (let* ((rawpub (rsa--openssh-key-to-rawpub key))
         (hash (md5 rawpub))
         (hexes (loop for i from 0 below (length hash) by 2
                      collect (substring hash i (+ i 2)))))
    (mapconcat (lambda (x) x) hexes ":")))

;;;
;;; Arithmetic calculation
;;;

(defun rsa-euclid (bn1 bn2)
  (if (rsa-bn:> bn1 bn2)
      (rsa-euclid-0 bn1 bn2)
    (rsa-euclid-0 bn2 bn1)))

;; http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
(defun rsa-euclid-0 (bn1 bn2)
  (loop with a = bn1
        with b = bn2
        with x = 0
        with y = 1
        with x-1 = 1
        with y-1 = 0
        with tmp
        until (rsa-bn:zerop b)
        do (let* ((q&r (rsa-bn:div&rem a b))
                  (q (car q&r))
                  (r (cdr q&r)))
             (setq a b)
             (setq b r)
             (setq tmp x)
             (setq x (rsa-bn:+ x-1 (rsa-bn:* q x)))
             (setq x-1 tmp)
             (setq tmp y)
             (setq y (rsa-bn:+ y-1 (rsa-bn:* q y)))
             (setq y-1 tmp))
        finally return
        (let ((tmp-x (rsa-bn:* bn1 x-1))
              (tmp-y (rsa-bn:* bn2 y-1)))
          (if (rsa-bn:< tmp-x tmp-y)
              (cons x-1 y-1)
            ;; make y coefficient to plus value
            (cons (rsa-bn:diff bn2 x-1)
                  (rsa-bn:diff bn1 y-1))))))

(if (fboundp 'unibyte-string)
    (defalias 'rsa--unibytes 'unibyte-string)
  (defun rsa--unibytes (&rest bytes)
    (string-as-unibyte (concat bytes))))

(defun rsa--read-bytes (bytes pos len)
  (loop with res = (aref bytes pos)
        with max-len = (length bytes)
        for i from (1+ pos) below (min (+ pos len) max-len)
        do (setq res (rsa-bn:logior
                      (rsa-bn:lshift res 8)
                      (aref bytes i)))
        finally return (cons res (if (= i max-len) nil i))))



;;;
;;; C oriented list manipulation
;;;

(defun rsa--listset (list idx value)
  (setcar (nthcdr idx list) value))

;; like memcpy
(defun rsa--listcpy (to from)
  (loop for x in from
        for i from 0
        do (rsa--listset to i x)))

;; like `memset'
(defun rsa--vecset (to start byte count)
  (loop for i from start
        repeat count
        do (aset to i byte)))



;;;
;;; handling bignum
;;;

(defun rsa-bn:from-bytes (text)
  (let ((hex (mapconcat (lambda (x) (format "%02x" x)) text "")))
    (rsa-bn:from-string hex 16)))

(defun rsa-bn:from-string (s &optional base)
  (let* ((str (format "%s#%s" (or base "16") s))
         (bn (math-read-number str)))
    bn))

(defun rsa-bn:to-bytes (bn)
  (let ((text (rsa--bn-to-text bn)))
    (append text nil)))

(defun rsa-bn:to-number (bn)
  (let* ((calc-number-radix 10)
         (dec (math-format-number bn)))
    (string-to-number dec)))

(defun rsa-bn:to-decimal (bn)
  (let ((calc-number-radix 10))
    (math-format-number bn)))

(defun rsa-bn:zerop (bn)
  (Math-zerop bn))

(defun rsa-bn:1- (bn)
  (rsa-bn:- bn 1))

(defun rsa-bn:1+ (bn)
  (rsa-bn:+ bn 1))

(defun rsa-bn:random-prime (bit)
  (loop with prime = nil
        until prime
        do (let ((r (rsa-bn:random bit)))
             (when (rsa-bn-prime-p r)
               (setq prime r)))
        finally return prime))

(defun rsa-bn-prime-p (bn)
  (with-temp-buffer
    (call-process "openssl"
                  nil (current-buffer) nil "prime"
                  (rsa-bn:to-decimal bn))
    (goto-char (point-min))
    (looking-at "[0-9a-zA-Z]+ is prime")))

(declare-function math-random-digits "calc-comb")

(defun rsa-bn:random (bit)
  (require 'calc-comb)
  (math-random-digits
   (ceiling (* bit (log10 2)))))

(defun rsa-bn:diff (bn1 bn2)
  (if (rsa-bn:> bn1 bn2)
      (rsa-bn:- bn1 bn2)
    (rsa-bn:- bn2 bn1)))

(defun rsa-bn:+ (bn1 bn2)
  (math-add bn1 bn2))

(defun rsa-bn:- (bn1 bn2)
  (math-sub bn1 bn2))

(defun rsa-bn:* (bn1 bn2)
  (math-mul bn1 bn2))

(defun rsa-bn:div&rem (dividend divisor)
  (math-idivmod dividend divisor))

(defun rsa-bn:% (dividend divisor)
  (destructuring-bind (_ . mod) (rsa-bn:div&rem dividend divisor)
    mod))

(defun rsa-bn:/ (dividend divisor)
  (destructuring-bind (div . _) (rsa-bn:div&rem dividend divisor)
    div))

(defun rsa-bn:sqrt (bn)
  (math-sqrt bn))

(defun rsa-bn:lcm (bn1 bn2)
  (let* ((gcd (math-gcd bn1 bn2))
         (div (rsa-bn:/ bn1 gcd)))
    (rsa-bn:* div bn2)))

(defun rsa-bn:= (bn1 bn2)
  (= (math-compare bn1 bn2) 0))

(defun rsa-bn:< (bn1 bn2)
  (< (math-compare bn1 bn2) 0))

(defun rsa-bn:> (bn1 bn2)
  (> (math-compare bn1 bn2) 0))

(defun rsa-bn:logior (bn1 bn2)
  (let* ((b1 (if (numberp bn1) (list bn1) (cdr bn1)))
         (b2 (if (numberp bn2) (list bn2) (cdr bn2)))
         (n (math-or-bignum b1 b2)))
    (cons 'bigpos n)))

(defun rsa-bn:logand (bn1 bn2)
  (let* ((b1 (if (numberp bn1) (list bn1) (cdr bn1)))
         (b2 (if (numberp bn2) (list bn2) (cdr bn2)))
         (n (math-and-bignum b1 b2)))
    (if n
        (cons 'bigpos n)
      0)))

(defun rsa-bn:read-bytes (bytes count &optional little-endian)
  (let* ((data (loop for b in bytes
                     repeat count
                     collect b into res
                     finally return
                     (progn
                       (when (< (length res) count)
                         (error "Unable read %s byte(s) from %s" count bytes))
                       res)))
         (value (rsa-bn:from-bytes data))
         (rest (nthcdr count bytes)))
    (list value rest)))

(defun rsa-bn:read-int32 (bytes &optional little-endian)
  (rsa-bn:read-bytes bytes 4 little-endian))

(defun rsa-bn:serialize (bn byte)
  (let* ((unibytes (rsa--bn-to-text bn))
         (0pad (make-list (- byte (length unibytes)) 0)))
    (apply 'rsa--unibytes (append 0pad unibytes nil))))

(defun rsa-bn:lshift (bn count)
  (if (minusp count)
      (rsa-bn:rshift bn (- count))
    (rsa-bn:* bn (math-pow 2 count))))

(defun rsa-bn:rshift (bn count)
  (if (minusp count)
      (rsa-bn:lshift bn (- count))
    (car (rsa-bn:div&rem bn (math-pow 2 count)))))

(defun rsa-bn:modulo-product (modulo bn1 bn2)
  (loop with pow = 1
        for b2 = bn2
        then (rsa-bn:rshift b2 1)
        for base = bn1
        then (rsa-bn:% (rsa-bn:* base base) modulo)
        until (rsa-bn:zerop b2)
        do (progn
             (unless (rsa-bn:zerop (rsa-bn:logand 1 b2))
               (setq pow (rsa-bn:% (rsa-bn:* pow base) modulo))))
        finally return pow))



(provide 'rsa)

;;; rsa.el ends here
