;;; cipher/rsa.el --- Encrypt/Decrypt string with RSA key.

;; Author: Masahiro Hayashi <mhayashi1120@gmail.com>
;; Keywords: data
;; URL: http://github.com/mhayashi1120/Emacs-cipher/raw/master/rsa.el
;; Emacs: GNU Emacs 22 or later
;; Version: 0.0.2
;; Package-Requires: ()

(defconst cipher/rsa-version "0.0.2")

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
;;     (require 'cipher/rsa)

;;; Usage:

;;; Sample:

;; * To encrypt our secret
;;   Please ensure that do not forget `clear-string' you want to hide.

;;TODO load public key from openssh
;; (defvar our-secret nil)

;; (let ((raw-string "Our Secret")
;;       (key (cipher/rsa-openssh-load-publine public-key-in-authorized_keys-file)))
;;   (setq our-secret (cipher/rsa-encrypt-string key raw-string))
;;   (clear-string raw-string))

;; * To decrypt `our-secret'

;;TODO load private key from openssh
;; (cipher/rsa-decrypt-string our-secret)

;;; TODO:

;; * generate key pair
;; * load openssh secret key
;; * ASN1 PEM technical term is correct?

;;; Code:

(eval-when-compile
  (require 'cl))

(defgroup cipher/rsa nil
  "Encrypt/Decrypt, Sign/Verify string with rsa key"
  :group 'environment)

(require 'calc)
(require 'calc-ext)
(require 'calc-bin)

(defcustom cipher/rsa-padding-method 'pkcs
  "Padding method to use."
  :group 'cipher/rsa
  :type '(choice
          (const pkcs)
          (const sslv23)
          (const oaep)))

;;;
;;; Interfaces
;;;

;;;###autoload
(defun cipher/rsa-encrypt-string (his-public-key string &optional coding-system)
  "Encrypt a well encoded STRING with HIS-PUBLIC-KEY to encrypted object
which can be decrypted by `cipher/rsa-decrypt-string'."
  (let* ((cs (or coding-system default-terminal-coding-system))
         (M (encode-coding-string string cs)))
    (cipher/rsa--encode-bytes M his-public-key nil)))

;;;###autoload
(defun cipher/rsa-decrypt-string (my-private-key encrypted-string &optional coding-system)
  "Decrypt a ENCRYPTED-STRING with MY-PRIVATE-KEY which was encrypted
by `cipher/rsa-encrypt-string'"
  (let ((M (cipher/rsa--decode-bytes encrypted-string my-private-key nil))
        (cs (or coding-system default-terminal-coding-system)))
    (decode-coding-string M cs)))

;;;###autoload
(defun cipher/rsa-encrypt-bytes (his-public-key string)
  "Encrypt a well encoded STRING with HIS-PUBLIC-KEY to encrypted object
which can be decrypted by `cipher/rsa-decrypt-string'."
  (cipher/rsa--check-unibyte-string string)
  (cipher/rsa--encode-bytes string his-public-key nil))

;;;###autoload
(defun cipher/rsa-decrypt-bytes (my-private-key encrypted-string)
  "Decrypt a ENCRYPTED-STRING with MY-PRIVATE-KEY which was encrypted
by `cipher/rsa-encrypt-bytes'"
  (cipher/rsa--check-unibyte-string encrypted-string)
  (cipher/rsa--decode-bytes encrypted-string my-private-key nil))

;;;###autoload
(defun cipher/rsa-sign-hash (my-private-key digest)
  "Sign DIGEST with MY-PRIVATE-KEY.
Returned value will be verified by `cipher/rsa-verify-hash'
with MY-PUBLIC-KEY. "
  (cipher/rsa--check-unibyte-string digest)
  (let* ((M digest)
         (sign (cipher/rsa--encode-bytes M my-private-key t)))
    sign))

;;;###autoload
(defun cipher/rsa-verify-hash (his-public-key sign digest)
  "Verify SIGN which created by `cipher/rsa-sign-hash' with private-key.
Decrypted unibyte string must equal DIGEST otherwise raise error.
"
  (cipher/rsa--check-unibyte-string digest)
  (let* ((verify (cipher/rsa--decode-bytes sign his-public-key t)))
    (unless (equal verify digest)
      (error "Sign must be `%s' but `%s'" digest verify))
    t))

;;;
;;; inner functions
;;;

(put 'cipher/rsa-decryption-failed
     'error-conditions '(cipher/rsa-decryption-failed error))
(put 'cipher/rsa-decryption-failed
     'error-message "Decoding error")

(put 'cipher/rsa-encryption-failed
     'error-conditions '(cipher/rsa-encryption-failed error))
(put 'cipher/rsa-encryption-failed
     'error-message "Encoding error")

(defun cipher/rsa--check-unibyte-string (s)
  (when (multibyte-string-p s)
    (error "Not a unibyte string `%s'" s)))

(defun cipher/rsa--bn-to-text (bn)
  (loop for (d . r) = (cipher/rsa-bn:div&rem bn 256)
        then (cipher/rsa-bn:div&rem d 256)
        collect r into res
        until (cipher/rsa-bn:zerop d)
        finally return (apply 'cipher/rsa--unibytes (nreverse res))))

(defun cipher/rsa--hex-to-bytes (hex)
  (loop with len = (length hex)
        for i from 0 below len by 2
        for j from (if (zerop (% len 2)) 2 1) by 2
        collect (string-to-number (substring hex i j) 16)))

(defun cipher/rsa--encode-bytes (text key sign-p)
  (let* ((n (cipher/rsa-key:N key))
         (e (if sign-p
                (cipher/rsa-key:D key)
              (cipher/rsa-key:E key)))
         (size (cipher/rsa-key-size key))
         ;;TODO difference between sign and encrypt
         (padded (cipher/rsa--padding-add text size))
         (M (cipher/rsa-bn:from-bytes padded))
         (C (cipher/rsa-bn:modulo-product n M e))
         (encrypt (cipher/rsa-bn:serialize C size)))
    encrypt))

(defun cipher/rsa--decode-bytes (encrypt key verify-p)
  (let ((n (cipher/rsa-key:N key))
        (size (cipher/rsa-key-size key)))
    (unless (= (length encrypt) size)
      (signal 'cipher/rsa-decryption-failed
              (list (format "Illegal length(%d) of encrypted text (%s)"
                            size encrypt))))
    (let* ((d (if verify-p
                  (cipher/rsa-key:E key)
                (cipher/rsa-key:D key)))
           (C (cipher/rsa-bn:from-bytes encrypt))
           (M (cipher/rsa-bn:modulo-product n C d))
           (padded (cipher/rsa-bn:serialize M size))
           (text (cipher/rsa--padding-remove padded)))
      text)))

;;;
;;; RSA padding algorithm
;;;

(defun cipher/rsa--random-memset (vec start len)
  (loop repeat len
        for i from start
        do (progn
             (aset vec i (let (r)
                           (while (zerop (setq r (random 256))))
                           r)))
        finally return i))

(defun cipher/rsa--xor-masking (data mask)
  (loop for m in mask
        for d in data
        for i from 0
        collect (logxor d m)))

(defun cipher/rsa--padding-sslv23-add (text size)
  (let ((len (length text))
        (allow-len (- size (+ 2 8 1))))
    (when (> len allow-len)
      (signal 'cipher/rsa-encryption-failed
              (list (format "Exceed limit (Must be smaller than %d but %d)"
                            allow-len len))))
    (let* ((suffix (make-list (- size len) 0))
           (origin (string-to-list text))
           (nulllen (- (length suffix) 3 8))
           (full (append suffix origin))
           (vec (apply 'cipher/rsa--unibytes full))
           (i 0))
      (aset vec 0 0)
      (aset vec 1 2)                    ; Public Key BT (Block Type)
      (setq i (cipher/rsa--random-memset vec 2 nulllen))
      (loop repeat 8
            do (progn
                 (aset vec i 3)
                 (setq i (1+ i))))
      (aset vec i 0)
      vec)))

(defun cipher/rsa--padding-sslv23-remove (text)
  (unless (= (aref text 0) 0)
    (signal 'cipher/rsa-encryption-failed
            (list "Expected null byte")))
  (loop for i from 1 below (length text)
        if (zerop (aref text i))
        return (substring text (1+ i))))

(defun cipher/rsa--padding-pkcs-add-1 (block-type text size filler)
  (let ((len (length text))
        (allow-len (- size (+ 2 8 1))))
    (when (> len allow-len)
      (signal 'cipher/rsa-encryption-failed
              (list (format "Exceed limit (Must be smaller than %d but %d)"
                            allow-len len))))
    (let* ((suffix (make-list (- size (length text)) 0))
           (origin (string-to-list text))
           (fill-len (- (length suffix) 3))
           (full (append suffix origin))
           (vec (apply 'cipher/rsa--unibytes full))
           (i 0))
      (aset vec 0 0)
      (aset vec 1 block-type)
      (setq i (funcall filler vec 2 fill-len))
      (aset vec i 0)
      vec)))

(defun cipher/rsa--padding-pkcs-add (text size)
  ;; 2: Public Key BT (Block Type)
  (cipher/rsa--padding-pkcs-add-1
   2 text size 'cipher/rsa--random-memset))

;;TODO not tested openssl 0.9.8 not yet supported?
(defun cipher/rsa--padding-pkcs-add2 (text size)
  ;; 1: Private Key BT (Block Type)
  (cipher/rsa--padding-pkcs-add-1
   1 text size
   (lambda (vec start len)
     (cipher/rsa--vecset vec start ?\xff len))))

(defun cipher/rsa--padding-pkcs-remove (text)
  (unless (= (aref text 0) 0)
    (signal 'cipher/rsa-encryption-failed
            (list "Expected null byte")))
  (loop for i from 1 below (length text)
        if (zerop (aref text i))
        return (substring text (1+ i))))

(defun cipher/rsa--padding-oaep-add (text size)
  (let* ((from (string-to-list text))
         (vhash (cipher/rsa--hex-to-bytes (sha1 "")))
         (sha1-len (length vhash))
         (max-len (- size 1 sha1-len sha1-len 1)))
    (when (minusp max-len)
      (signal 'cipher/rsa-encryption-failed
              (list "Key size too small")))
    (when (> (length text) max-len)
      (signal 'cipher/rsa-encryption-failed
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
            do (cipher/rsa--listset db i b))
      (cipher/rsa--listcpy (last db (+ 1 (length from))) (cons 1 from))
      ;; set seed
      (loop repeat sha1-len
            for i from 0
            do (cipher/rsa--listset seed i (random 256)))

      ;; XOR masking
      (let* ((dbmask (cipher/rsa--oaep-MGF seed (length db)))
             (maskeddb (cipher/rsa--xor-masking db dbmask))
             (seedmask (cipher/rsa--oaep-MGF maskeddb (length seed)))
             (maskedseed (cipher/rsa--xor-masking seed seedmask)))
        (cons 0 (append maskedseed maskeddb))))))

(defun cipher/rsa--padding-oaep-remove (text)
  ;; ignore Side-Channel attack.
  ;; No need to concern about it in elisp.
  (let* ((from (string-to-list text))
         (taker (lambda (n l)
                  (loop repeat n
                        for x in l
                        collect x)))
         ;; to verify hash
         (vhash (cipher/rsa--hex-to-bytes (sha1 "")))
         (sha1-len (length vhash))
         (maskedseed (funcall taker sha1-len (nthcdr 1 from)))
         (maskeddb (copy-sequence (nthcdr (+ 1 sha1-len) from)))
         ;; XOR unmasking
         (seedmask (cipher/rsa--oaep-MGF maskeddb sha1-len))
         (seed (cipher/rsa--xor-masking seedmask maskedseed))
         (dbmask (cipher/rsa--oaep-MGF seed (length maskeddb)))
         (db (cipher/rsa--xor-masking dbmask maskeddb))
         (hash (funcall taker sha1-len db)))
    (unless (equal vhash hash)
      (signal 'cipher/rsa-decryption-failed (list "Hash is changed")))
    (loop for xs on (nthcdr sha1-len db)
          while (zerop (car xs))
          finally return
          (let ((data (cdr xs)))
            (unless (= (car xs) 1)
              (signal 'cipher/rsa-decryption-failed (list "No digit")))
            (apply 'cipher/rsa--unibytes data)))))

(defun cipher/rsa--oaep-MGF (seed require-len)
  (loop for i from 0
        while (< (length out) require-len)
        append
        (let* ((cnt (list
                     (logand (lsh i -24) ?\xff)
                     (logand (lsh i -16) ?\xff)
                     (logand (lsh i  -8) ?\xff)
                     (logand      i      ?\xff)))
               (bytes (apply 'cipher/rsa--unibytes (append seed cnt))))
          (cipher/rsa--hex-to-bytes (sha1 bytes)))
        into out
        finally return (loop repeat require-len
                             for b in out
                             collect b)))

(defun cipher/rsa--padding-add (text size)
  (let ((func (intern-soft
               (format "cipher/rsa--padding-%s-add"
                       cipher/rsa-padding-method))))
    (cond
     ((fboundp func)
      (funcall func text size)
      ;; (cipher/rsa--padding-pkcs-add2 text size)
      )
     (t
      (error "Not supported type %s"
             cipher/rsa-padding-method)))))

(defun cipher/rsa--padding-remove (text)
  (let ((func (intern-soft
               (format "cipher/rsa--padding-%s-remove"
                       cipher/rsa-padding-method))))
    (cond
     ((fboundp func)
      (funcall func text))
     (t
      (error "Not supported type %s"
             cipher/rsa-padding-method)))))

;;;
;;; Handling key
;;;

(defun cipher/rsa-key-size (key)
  (loop with n = (cipher/rsa-key:N key)
        until (cipher/rsa-bn:zerop n)
        for i from 0
        do (setq n (cipher/rsa-bn:rshift n 1))
        finally return (+ (/ i 8)
                          (if (zerop (% i 8)) 0 1))))

(defun cipher/rsa-generate-key (bits &optional comment)
  ;;TODO
  (let* ((p (cipher/rsa-bn:random-prime (/ bits 2)))
         (q (cipher/rsa-bn:random-prime (/ bits 2)))
         (n (cipher/rsa-bn:* p q))
         (L (cipher/rsa-bn:lcm
             (cipher/rsa-bn:1- p) (cipher/rsa-bn:1- q)))
         (e 11)                ;TODO 4th felmar 65537
         (d (cdr (cipher/rsa-euclid L e))))
    (when (cipher/rsa-bn:= d 1)
      (setq e 65537)
      (setq d (cdr (cipher/rsa-euclid L e))))
    ;;TODO
    (cipher/rsa-key:make comment n e d)))

(defun cipher/rsa-key:export-public (key)
  (cipher/rsa-key:make
   (cipher/rsa-key:comment key)
   (cipher/rsa-key:N key)
   (cipher/rsa-key:E key)
   nil))

(defun cipher/rsa-key:secret-p (key)
  (and (cipher/rsa-key:D key) t))

(defun cipher/rsa-key:make (comment n e d)
  (list comment n e d))

(defun cipher/rsa-key:comment (key)
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

(defun cipher/rsa--insert-file-as-binary (file)
  (set-buffer-multibyte nil)
  (let ((coding-system-for-read 'binary))
    (insert-file-contents file)))

(defun cipher/rsa-openssh-load-key (file)
  (with-temp-buffer
    (cipher/rsa--insert-file-as-binary file)
    ;; Decode openssh or openssl secret key file.
    (cipher/rsa--openssh-decrypt-maybe file)
    (let* ((data (string-to-list (buffer-string)))
           (blocks (cipher/rsa--asn1-read-blocks data)))
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
      (cipher/rsa-key:make
       nil
       (cipher/rsa-bn:from-bytes (nth 1 blocks))
       (cipher/rsa-bn:from-bytes (nth 2 blocks))
       (cipher/rsa-bn:from-bytes (nth 3 blocks))))))

(defun cipher/rsa--asn1-read-blocks (data)
  (destructuring-bind (tag seqlen seq)
      (cipher/rsa--asn1-read-object data)
    ;;TODO check tag?
    ;; (unless (= tag ?\x30)
    ;;   (error "TODO"))
    (unless (= seqlen (length seq))
      (signal 'invalid-read-syntax (list "Unexpected bytes")))
    (loop with list = seq
          while list
          collect (destructuring-bind (tag len rest)
                      (cipher/rsa--asn1-read-object list)
                    (loop repeat len
                          for xs on rest
                          collect (car xs)
                          finally (setq list xs))))))

;; '(inf ret rest)
(defun cipher/rsa--asn1-read-length (list)
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

(defun cipher/rsa--asn1-read-object (list)
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
    (destructuring-bind (len rest) (cipher/rsa--asn1-read-length list)
      (list tag len rest))))

(defun cipher/rsa-openssh-load-pubkey (pub-file)
  (with-temp-buffer
    (cipher/rsa--insert-file-as-binary pub-file)
    (goto-char (point-min))
    (cond
     ((looking-at "^ssh-rsa ")
      (cipher/rsa-openssh-load-publine (buffer-string)))
     ((looking-at "^-----BEGIN PUBLIC KEY-----")
      (cipher/rsa--read-openssl-pubkey))
     (t
      (error "Unrecognized format %s" pub-file)))))

(defun cipher/rsa--read-openssl-pubkey ()
  (unless (re-search-forward "^-----BEGIN PUBLIC KEY-----" nil t)
    (signal 'invalid-read-syntax (list "No public key header")))
  (let ((start (point)))
    (unless (re-search-forward "^-----END PUBLIC KEY-----" nil t)
      (signal 'invalid-read-syntax (list "No public key footer")))
    (let* ((end (match-beginning 0))
           (str (buffer-substring start end))
           (raw (base64-decode-string str))
           (data (string-to-list raw))
           (top-blocks (cipher/rsa--asn1-read-blocks data))
           ;; public key have recursive structure.
           (bit-string (nth 1 top-blocks))
           (blocks (cipher/rsa--asn1-read-blocks
                    (loop for xs on bit-string
                          unless (zerop (car xs))
                          return xs))))
      ;; ASN1_SEQUENCE_cb(RSAPublicKey, rsa_cb) = {
      ;;        ASN1_SIMPLE(RSA, n, BIGNUM),
      ;;        ASN1_SIMPLE(RSA, e, BIGNUM),
      ;; } ASN1_SEQUENCE_END_cb(RSA, RSAPublicKey)
      (cipher/rsa-key:make
       nil
       (cipher/rsa-bn:from-bytes (nth 0 blocks))
       (cipher/rsa-bn:from-bytes (nth 1 blocks))
       nil))))

(defconst cipher/rsa--re-openssh-publine
  (concat
   "\\`"
   "ssh-rsa "
   "\\([a-zA-Z0-9+/]+=*\\)"
   "\\(?: \\(.*\\)\\)?"))

(defun cipher/rsa-openssh-load-publine (pub-line)
  (unless (string-match cipher/rsa--re-openssh-publine pub-line)
    (error "Not a rsa public key line"))
  (let* ((key (match-string 1 pub-line))
         (comment (match-string 2 pub-line))
         (binary (append (base64-decode-string key) nil))
         (blocks (cipher/rsa--read-publine-blocks binary)))
    (destructuring-bind (type e n) blocks
      (let (
            ;; ignore sign byte by `cdr'
            (N (cipher/rsa-bn:from-bytes (cdr n))) 
            (E (cipher/rsa-bn:from-bytes e)))
        (list comment N E)))))

(defun cipher/rsa--read-publine-blocks (string)
  (let ((bytes (append string nil))
        data res)
    (while bytes
      (let* ((tmp (cipher/rsa-bn:read-int32 bytes))
             (len (cipher/rsa-bn:to-number (car tmp))))
        (setq bytes (cadr tmp))
        (loop for bs on bytes
              repeat len
              collect (car bs) into res
              finally (setq data res
                            bytes bs))
        (setq res (cons data res))))
    (nreverse res)))

(declare-function cipher/aes-decrypt-by-key "aes")

(defun cipher/rsa--openssh-decrypt-maybe (file)
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
               (iv-bytes (cipher/rsa--hex-to-bytes hex-iv))
               ;; required only 8 bytes to create key
               (iv-8 (loop repeat 8 for b in iv-bytes collect b))
               (A (md5 (apply 'cipher/rsa--unibytes (append pass iv-8))))
               (B (md5 (apply
                        'cipher/rsa--unibytes
                        (append (cipher/rsa--hex-to-bytes A) pass iv-8))))
               (C (md5 (apply
                        'cipher/rsa--unibytes
                        (append (cipher/rsa--hex-to-bytes B) pass iv-8)))))
          (setq iv (vconcat iv-bytes))
          (setq key (vconcat (cipher/rsa--hex-to-bytes (concat A B))))
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
(defun cipher/rsa-openssh-load-key2 (file)
  (require 'asn1)
  (with-temp-buffer
    (cipher/rsa--insert-file-as-binary file)
    ;; Decode openssh or openssl secret key file.
    (cipher/rsa--openssh-decrypt-maybe file)
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
      (cipher/rsa-key:make
       nil
       (cipher/rsa-bn:from-bytes (asn1-value (nth 1 asn1-top)))
       (cipher/rsa-bn:from-bytes (asn1-value (nth 2 asn1-top)))
       (cipher/rsa-bn:from-bytes (asn1-value (nth 3 asn1-top)))))))

;; testing 
(defun cipher/rsa--read-openssl-pubkey2 ()
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
      (cipher/rsa-key:make
       nil
       (cipher/rsa-bn:from-bytes (asn1-value (nth 0 asn1-top)))
       (cipher/rsa-bn:from-bytes (asn1-value (nth 1 asn1-top)))
       nil))))

;; openssh-5.9p1/key.c
(defun cipher/rsa--openssh-key-to-rawpub (key)
  (let* ((key-type "ssh-rsa")
         (klen (cipher/rsa-bn:serialize (length key-type) 4))
         (serializer (lambda (x)
                       (let ((bs (cipher/rsa-bn:to-bytes x)))
                         (if (plusp (logand (car bs) ?\x80))
                             (cons 0 bs)
                           bs))))
         (E (cipher/rsa-key:E key))
         (e (funcall serializer E))
         (elen (cipher/rsa-bn:serialize (length e) 4))
         (N (cipher/rsa-key:N key))
         (n (funcall serializer N))
         (nlen (cipher/rsa-bn:serialize (length n) 4))
         (raw (append
               (append klen nil)
               (string-to-list key-type)
               (append elen nil)
               e
               (append nlen nil)
               n)))
    (apply 'cipher/rsa--unibytes raw)))

(defun cipher/rsa-openssh-key-to-publine (key)
  (let ((raw (cipher/rsa--openssh-key-to-rawpub key)))
    (format
     "ssh-rsa %s"
     (base64-encode-string raw t))))

(defun cipher/rsa-openssh-pubkey-fingerprint (key)
  (let* ((rawpub (cipher/rsa--openssh-key-to-rawpub key))
         (hash (md5 rawpub))
         (hexes (loop for i from 0 below (length hash) by 2
                      collect (substring hash i (+ i 2)))))
    (mapconcat (lambda (x) x) hexes ":")))

;;;
;;; Arithmetic calculation
;;;

(defun cipher/rsa-euclid (bn1 bn2)
  (if (cipher/rsa-bn:> bn1 bn2)
      (cipher/rsa-euclid-0 bn1 bn2)
    (cipher/rsa-euclid-0 bn2 bn1)))

;; http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
(defun cipher/rsa-euclid-0 (bn1 bn2)
  (loop with a = bn1
        with b = bn2
        with x = 0
        with y = 1
        with x-1 = 1
        with y-1 = 0
        with tmp
        until (cipher/rsa-bn:zerop b)
        do (let* ((q&r (cipher/rsa-bn:div&rem a b))
                  (q (car q&r))
                  (r (cdr q&r)))
             (setq a b)
             (setq b r)
             (setq tmp x)
             (setq x (cipher/rsa-bn:+ x-1 (cipher/rsa-bn:* q x)))
             (setq x-1 tmp)
             (setq tmp y)
             (setq y (cipher/rsa-bn:+ y-1 (cipher/rsa-bn:* q y)))
             (setq y-1 tmp))
        finally return
        (let ((tmp-x (cipher/rsa-bn:* bn1 x-1))
              (tmp-y (cipher/rsa-bn:* bn2 y-1)))
          (if (cipher/rsa-bn:< tmp-x tmp-y)
              (cons x-1 y-1)
            ;; make y coefficient to plus value
            (cons (cipher/rsa-bn:diff bn2 x-1)
                  (cipher/rsa-bn:diff bn1 y-1))))))

(if (fboundp 'unibyte-string)
    (defalias 'cipher/rsa--unibytes 'unibyte-string)
  (defun cipher/rsa--unibytes (&rest bytes)
    (string-as-unibyte (concat bytes))))

(defun cipher/rsa--read-bytes (bytes pos len)
  (loop with res = (aref bytes pos)
        with max-len = (length bytes)
        for i from (1+ pos) below (min (+ pos len) max-len)
        do (setq res (cipher/rsa-bn:logior
                      (cipher/rsa-bn:lshift res 8)
                      (aref bytes i)))
        finally return (cons res (if (= i max-len) nil i))))



;;;
;;; C oriented list manipulation
;;;

(defun cipher/rsa--listset (list idx value)
  (setcar (nthcdr idx list) value))

;; like memcpy
(defun cipher/rsa--listcpy (to from)
  (loop for x in from
        for i from 0
        do (cipher/rsa--listset to i x)))

;; like `memset'
(defun cipher/rsa--vecset (to start byte count)
  (loop for i from start
        repeat count
        do (aset to i byte)))



;;;
;;; handling bignum
;;;

(defun cipher/rsa-bn:from-bytes (text)
  (let ((hex (mapconcat (lambda (x) (format "%02x" x)) text "")))
    (cipher/rsa-bn:from-string hex 16)))

(defun cipher/rsa-bn:from-string (s &optional base)
  (let* ((str (format "%s#%s" (or base "16") s))
         (bn (math-read-number str)))
    bn))

(defun cipher/rsa-bn:to-bytes (bn)
  (let ((text (cipher/rsa--bn-to-text bn)))
    (append text nil)))

(defun cipher/rsa-bn:to-number (bn)
  (let* ((calc-number-radix 10)
         (dec (math-format-number bn)))
    (string-to-number dec)))

(defun cipher/rsa-bn:to-decimal (bn)
  (let ((calc-number-radix 10))
    (math-format-number bn)))

(defun cipher/rsa-bn:zerop (bn)
  (Math-zerop bn))

(defun cipher/rsa-bn:1- (bn)
  (cipher/rsa-bn:- bn 1))

(defun cipher/rsa-bn:1+ (bn)
  (cipher/rsa-bn:+ bn 1))

(defun cipher/rsa-bn:random-prime (bit)
  (loop with prime = nil
        until prime
        do (let ((r (cipher/rsa-bn:random bit)))
             (when (cipher/rsa-bn-prime-p r)
               (setq prime r)))
        finally return prime))

(defun cipher/rsa-bn-prime-p (bn)
  (with-temp-buffer
    (call-process "openssl"
                  nil (current-buffer) nil "prime"
                  (cipher/rsa-bn:to-decimal bn))
    (goto-char (point-min))
    (looking-at "[0-9a-zA-Z]+ is prime")))

(declare-function math-random-digits "calc-comb")

(defun cipher/rsa-bn:random (bit)
  (require 'calc-comb)
  (math-random-digits
   (ceiling (* bit (log10 2)))))

(defun cipher/rsa-bn:diff (bn1 bn2)
  (if (cipher/rsa-bn:> bn1 bn2)
      (cipher/rsa-bn:- bn1 bn2)
    (cipher/rsa-bn:- bn2 bn1)))

(defun cipher/rsa-bn:+ (bn1 bn2)
  (math-add bn1 bn2))

(defun cipher/rsa-bn:- (bn1 bn2)
  (math-sub bn1 bn2))

(defun cipher/rsa-bn:* (bn1 bn2)
  (math-mul bn1 bn2))

(defun cipher/rsa-bn:div&rem (dividend divisor)
  (math-idivmod dividend divisor))

(defun cipher/rsa-bn:% (dividend divisor)
  (destructuring-bind (_ . mod) (cipher/rsa-bn:div&rem dividend divisor)
    mod))

(defun cipher/rsa-bn:/ (dividend divisor)
  (destructuring-bind (div . _) (cipher/rsa-bn:div&rem dividend divisor)
    div))

(defun cipher/rsa-bn:sqrt (bn)
  (math-sqrt bn))

(defun cipher/rsa-bn:lcm (bn1 bn2)
  (let* ((gcd (math-gcd bn1 bn2))
         (div (cipher/rsa-bn:/ bn1 gcd)))
    (cipher/rsa-bn:* div bn2)))

(defun cipher/rsa-bn:= (bn1 bn2)
  (= (math-compare bn1 bn2) 0))

(defun cipher/rsa-bn:< (bn1 bn2)
  (< (math-compare bn1 bn2) 0))

(defun cipher/rsa-bn:> (bn1 bn2)
  (> (math-compare bn1 bn2) 0))

(defun cipher/rsa-bn:logior (bn1 bn2)
  (let* ((b1 (if (numberp bn1) (list bn1) (cdr bn1)))
         (b2 (if (numberp bn2) (list bn2) (cdr bn2)))
         (n (math-or-bignum b1 b2)))
    (cons 'bigpos n)))

(defun cipher/rsa-bn:logand (bn1 bn2)
  (let* ((b1 (if (numberp bn1) (list bn1) (cdr bn1)))
         (b2 (if (numberp bn2) (list bn2) (cdr bn2)))
         (n (math-and-bignum b1 b2)))
    (if n
        (cons 'bigpos n)
      0)))

(defun cipher/rsa-bn:read-bytes (bytes count &optional little-endian)
  (let* ((data (loop for b in bytes
                     repeat count
                     collect b into res
                     finally return
                     (progn
                       (when (< (length res) count)
                         (error "Unable read %s byte(s) from %s" count bytes))
                       res)))
         (value (cipher/rsa-bn:from-bytes data))
         (rest (nthcdr count bytes)))
    (list value rest)))

(defun cipher/rsa-bn:read-int32 (bytes &optional little-endian)
  (cipher/rsa-bn:read-bytes bytes 4 little-endian))

(defun cipher/rsa-bn:serialize (bn byte)
  (let* ((unibytes (cipher/rsa--bn-to-text bn))
         (0pad (make-list (- byte (length unibytes)) 0)))
    (apply 'cipher/rsa--unibytes (append 0pad unibytes nil))))

(defun cipher/rsa-bn:lshift (bn count)
  (if (minusp count)
      (cipher/rsa-bn:rshift bn (- count))
    (cipher/rsa-bn:* bn (math-pow 2 count))))

(defun cipher/rsa-bn:rshift (bn count)
  (if (minusp count)
      (cipher/rsa-bn:lshift bn (- count))
    (car (cipher/rsa-bn:div&rem bn (math-pow 2 count)))))

(defun cipher/rsa-bn:modulo-product (modulo bn1 bn2)
  (loop with pow = 1
        for b2 = bn2
        then (cipher/rsa-bn:rshift b2 1)
        for base = bn1
        then (cipher/rsa-bn:% (cipher/rsa-bn:* base base) modulo)
        until (cipher/rsa-bn:zerop b2)
        do (progn
             (unless (cipher/rsa-bn:zerop (cipher/rsa-bn:logand 1 b2))
               (setq pow (cipher/rsa-bn:% (cipher/rsa-bn:* pow base) modulo))))
        finally return pow))



(provide 'cipher/rsa)

;;; cipher/rsa.el ends here
