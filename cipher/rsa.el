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
;;     (require 'cipher/rsa)

;;; Usage:

;;; Sample:

;; * To encrypt our secret
;;   Please ensure that do not forget `clear-string' you want to hide.

;;TODO load public key from openssh
;; (defvar our-secret nil)

;; (let ((raw-string "Our Secret"))
;;   (setq our-secret (cipher/rsa-encrypt-string raw-string))
;;   (clear-string raw-string))

;; * To decrypt `our-secret'

;;TODO load private key from openssh
;; (cipher/rsa-decrypt-string our-secret)

;;; TODO:

;; * generate key pair
;; * load openssh secret key

;;; Code:

(eval-when-compile
  (require 'cl))

(require 'calc)
(require 'calc-ext)
(require 'calc-bin)

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
(defun cipher/rsa-sign-hash (my-private-key hash)
  "Sign HASH with MY-PRIVATE-KEY. 
Returned value will be verified with `cipher/rsa-verify-hash'
with my-public-key. "
  (let* ((M hash)
         (sign (cipher/rsa--sign-bytes M my-private-key)))
    (base64-encode-string sign t)))

;;;###autoload
(defun cipher/rsa-verify-hash (his-public-key sign hash)
  "Verify SIGN which created with `cipher/rsa-sign-hash' by private-key.
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

(defvar cipher/rsa--max-encode-length 255
  "Hiding parameter size of text to encrypt.")

(defun cipher/rsa--encode-bytes (M e key &optional block-size)
  (when (> (length M) cipher/rsa--max-encode-length)
    (error "Exceed limit (%d)" cipher/rsa--max-encode-length))
  (let* ((n (cipher/rsa-key:N key))
         (size (or block-size
                   (cipher/rsa-key-size key))))
    (loop for c across M
          concat (let ((C (cipher/rsa--encrypt-char c e n)))
                   (cipher/rsa-bn:serialize C size)))))

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
    (loop for (bC rest) = (cipher/rsa-bn:read-bytes lC size) 
          then (and rest (cipher/rsa-bn:read-bytes rest size))
          while bC
          collect (cipher/rsa--decrypt-char bC d n)
          into res
          finally return (apply 'cipher/rsa--unibyte-string res))))

(defun cipher/rsa--encrypt-char (M e n)
  (let* ((M2 (+ M 2))
         (C (cipher/rsa-bn:modulo-product n M2 e)))
    C))

(defun cipher/rsa--decrypt-char (C d n)
  (let* ((M (cipher/rsa-bn:modulo-product n C d)))
    (- M 2)))

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

(defun cipher/rsa-generate-key (name bits)
  ;;TODO
  (let* ((p (cipher/rsa-bn:random-prime (/ bits 2)))
         (q (cipher/rsa-bn:random-prime (/ bits 2)))
         (n (cipher/rsa-bn:* p q))
         (L (cipher/rsa-bn:lcm (cipher/rsa-bn:1- p) (cipher/rsa-bn:1- q)))
         (e 11)                ;TODO 4th felmar 65537
         (d (cdr (cipher/rsa-euclid L e))))
    (when (cipher/rsa-bn:= d 1)
      (setq e 65537)
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
  (and (cipher/rsa-key:D key) t))

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
    (cipher/rsa-openssh-key)))

(defun cipher/rsa-openssh-key ()
  (cipher/rsa--openssh-decrypt-buffer)
  (let ((coding-system-for-write 'binary))
    (call-process-region 
     (point-min) (point-max) "openssl" t t nil "asn1parse" "-inform" "DER"))
  (let (res)
    (goto-char (point-min))
    (while (re-search-forward "prim: INTEGER[ \t]+:\\([0-9A-Fa-f]+\\)" nil t)
      (setq res (cons (match-string 1) res)))
    (setq res (nreverse res))
    (list nil
          (cipher/rsa-bn:from-string (nth 1 res))
          (cipher/rsa-bn:from-string (nth 2 res))
          (cipher/rsa-bn:from-string (nth 3 res)))))

(defun cipher/rsa-openssh-load-pubkey (pub-file)
  (with-temp-buffer
    (insert-file-contents pub-file)
    (goto-char (point-min))
    (cond
     ((looking-at "^ssh-rsa ")
      (cipher/rsa--openssh-publine (buffer-string)))
     ((looking-at "^-----BEGIN PUBLIC KEY-----")
      (cipher/rsa--read-openssl-pubkey))
     (t
      (error "Unrecognized format %s" pub-file)))))

(defun cipher/rsa--read-openssl-pubkey ()
  ;;TODO
  )

(defun cipher/rsa--openssh-publine (pub-line)
  (unless (string-match "^ssh-rsa \\([a-zA-Z0-9+/]+=*\\)\\(?: \\(.*\\)\\)?" pub-line)
    (error "Not a rsa public key line"))
  (let* ((key (match-string 1 pub-line))
         (comment (match-string 2 pub-line))
         (binary (append (base64-decode-string key) nil))
         (blocks (cipher/rsa--read-publine-blocks binary)))
    (destructuring-bind (type e n) blocks
      (let* ((tobn (lambda (bs)
                     (cipher/rsa-bn:from-string
                      (mapconcat (lambda (x) (format "%02x" x)) bs "")
                      16)))
             ;; ignore sign byte by `cdr'
             (N (funcall tobn (cdr n)))
             (E (funcall tobn e)))
        (list comment N E)))))

(defun cipher/rsa--read-publine-blocks (string)
  (let ((bytes (append string nil))
        res tmp len data)
    (while bytes
      (setq tmp (cipher/rsa-bn:read-int32 bytes))
      (setq len (cipher/rsa-bn:to-number (car tmp))
            bytes (cadr tmp))
      (loop for bs on bytes
            repeat len
            collect (car bs) into res
            finally (setq data res
                          bytes bs))
      (setq res (cons data res)))
    (nreverse res)))

(defun cipher/rsa--openssh-decrypt-buffer ()
  (save-excursion
    (goto-char (point-min))
    (unless (re-search-forward "^-----BEGIN RSA PRIVATE KEY-----" nil t)
      (signal 'invalid-read-syntax (list "No base64 data")))
    (let (key algorithm iv)
      (when (and (re-search-forward "^Proc-Type: " nil t)
                 (re-search-forward "^DEK-Info: *\\([^,]+\\),\\(.*\\)" nil t))
        (setq algorithm (downcase (match-string 1)))
        (let* ((hex-iv (match-string 2))
               (pass (vconcat (read-passwd "Password: ")))
               (iv-bytes (cipher/rsa--hex-to-bytes hex-iv))
               ;; required only 8 bytes to create key
               (iv-8 (loop repeat 8 for b in iv-bytes collect b))
               (A (md5 (apply 'unibyte-string (append pass iv-8))))
               (B (md5 (apply
                        'unibyte-string
                        (append (cipher/rsa--hex-to-bytes A) pass iv-8))))
               (C (md5 (apply
                        'unibyte-string
                        (append (cipher/rsa--hex-to-bytes B) pass iv-8)))))
          (setq iv (vconcat iv-bytes))
          (setq key (vconcat (cipher/rsa--hex-to-bytes (concat A B))))
          (unless (re-search-forward "^$" nil t)
            (signal 'invalid-read-syntax (list "No header separator")))))
      (let ((start (point)))
        (unless (re-search-forward "^-----END RSA PRIVATE KEY-----" nil t)
          (signal 'invalid-read-syntax (list "No footer")))
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
          (insert data))))))

(defun cipher/rsa--hex-to-bytes (hex)
  (loop with len = (length hex)
        for i from 0 below len by 2
        for j from (if (zerop (% len 2)) 2 1) by 2
        collect (string-to-number (substring hex i j) 16)))

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
    (defalias 'cipher/rsa--unibyte-string 'unibyte-string)
  (defun cipher/rsa--unibyte-string (&rest bytes)
    (concat bytes)))

(defun cipher/rsa--read-bytes (bytes pos len)
  (loop with res = (aref bytes pos)
        with max-len = (length bytes)
        for i from (1+ pos) below (min (+ pos len) max-len)
        do (setq res (cipher/rsa-bn:logior 
                      (cipher/rsa-bn:lshift res 8)
                      (aref bytes i)))
        finally return (cons res (if (= i max-len) nil i))))



(defun cipher/rsa-bn:from-string (s &optional base)
  (let* ((str (format "%s#%s" (or base "16") s))
         (bn (math-read-number str)))
    bn))

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
  (cipher/rsa-bn:- bn 1))

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

;; euclid division
(defun cipher/rsa-bn:gcd (m n)
  (loop with res = m
        with tmp = nil
        until (cipher/rsa-bn:zerop n)
        do (setq res n
                 tmp (cipher/rsa-bn:% m n))
        until (cipher/rsa-bn:zerop tmp)
        do (progn (setq m n) (setq n tmp))
        finally return res))

(defun cipher/rsa-bn:lcm (bn1 bn2)
  (let* ((gcd (cipher/rsa-bn:gcd bn1 bn2))
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

(defun cipher/rsa-bn:from-bytes (bytes &optional little-endian)
  (let ((hex (mapconcat
              (lambda (x) (format "%02x" x))
               (if little-endian (nreverse bytes) bytes)
               "")))
    (cipher/rsa-bn:from-string hex 16)))

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

(defun cipher/rsa-bn:serialize (bn byte &optional little-endian allow-overflow)
  (let* ((bytes (loop for (div . rem) = (cons bn nil)
                      then (cipher/rsa-bn:div&rem div ?\x100)
                      until (cipher/rsa-bn:zerop div)
                      if rem
                      collect rem into res
                      finally return (mapcar 
                                      (lambda (x) (cipher/rsa-bn:to-number x))
                                      (cons rem (nreverse res)))))
         (len (length bytes))
         (block (cond
                 ((> len byte) 
                  (unless allow-overflow
                    (signal 'arith-error (list "Overflow" bn)))
                  (nthcdr (- len byte) bytes))
                 (t
                  (append (make-list (- byte len) 0) bytes)))))
    (vconcat
     (if little-endian
         (nreverse block)
       block))))

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
