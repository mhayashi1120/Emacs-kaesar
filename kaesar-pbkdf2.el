;;; kaesar-pbkdf2.el --- PBKDF2 extension for kaesar.el -*- lexical-binding: t -*-

;; Author: Masahiro Hayashi <mhayashi1120@gmail.com>
;; Keywords: data
;; URL: https://github.com/mhayashi1120/Emacs-kaesar
;; Emacs: GNU Emacs 25.1 or later
;; Version: 0.9.4
;; Package-Requires: ((emacs "25.1"))

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

;;; Commentary:

;; Extension pacakge for kaesar.el . The latest (at least 2023-02-21) `openssl`
;; key derivation use the algorithm.
;;
;; NOTE: PBKDF2 is `Password-Based Key Derivation Function 2`

;;; Code:

(require 'cl-lib)
(require 'pcase)

(defun kaesar-pbkdf2--pack (size n)
  (cl-loop repeat size
           for i from 0
           collect (logand (ash n (* i -8)) #xff) into r
           finally return (nreverse r)))

(defun kaesar-pbkdf2--logxor (u1 u2)
  (unless (= (length u1) (length u2))
    (error "Not a same length of vector"))
  (cl-mapcar
   (lambda (b1 b2) (logxor b1 b2))
   u1 u2))

(defconst kaesar-pbkdf2-hmac-algorithms
  ;; (ALGORITHM BLOCK-SIZE SIZE)
  '(
    (md5 64 16)
    (sha1 64 20)
    (sha224 64 28)
    (sha256 64 32)
    (sha384 128 48)
    (sha512 128 64)))

;; Restricted support HMAC (RFC2104)
;; ref: https://tools.ietf.org/rfc/rfc2104.txt
(defun kaesar-pbkdf2-tiny-hmac (algorithm password message)
  (when (< 4096 (length message))
    (error "Large size message not supported"))
  (when (multibyte-string-p password)
    (error "Multibyte string not supported as password"))
  (when (multibyte-string-p message)
    (error "Multibyte string not supported as message"))
  (pcase-exhaustive (assoc algorithm kaesar-pbkdf2-hmac-algorithms)
    (`(,_ ,block-size . ,_)
     (when (< block-size (length password))
       (setq password (secure-hash algorithm password nil nil t)))
     (when (< (length password) block-size)
       (setq password (apply #'unibyte-string
                             (append (string-to-list password)
                                     (make-list (- block-size (length password)) 0)))))
     (let* ((opad (cl-loop for p across password
                           for b in (make-list block-size #x5c)
                           collect (logxor p b)))
            (ipad (cl-loop for p across password
                           for b in (make-list block-size #x36)
                           collect (logxor p b)))
            (ipad* (apply #'unibyte-string (append ipad (string-to-list message))))
            (digest (secure-hash algorithm ipad* nil nil t))
            (opad* (apply #'unibyte-string (append opad (string-to-list digest)))))
       (secure-hash algorithm opad* nil nil t)))))

(defun kaesar-pbkdf2--check-natural (x)
  (unless (and (integerp x) (cl-plusp x))
    (error "Not a natural number %s" x)))

;;;###autoload
(defun kaesar-pbkdf2-hmac (password iter size &optional salt algorithm)
  "PASSWORD as string ITER as integer SIZE as integer return list of byte.
Optional SALT as list (also allow string) of byte.
Optional ALGORITHM should be listed in `hmac-algorithm-blocksizes` ."
  (kaesar-pbkdf2--check-natural iter)
  (kaesar-pbkdf2--check-natural size)
  (setq algorithm (or algorithm 'sha256))
  (setq salt (or salt ()))

  (pcase-exhaustive (assoc algorithm kaesar-pbkdf2-hmac-algorithms)
    (`(,_ ,_ ,hash-size)
     (when (< (* #xffffffff hash-size) size)
       (error "Invalid length of request %s" size))))

  (let* ((PRF (lambda (U)
                (let* ((bytes (apply #'unibyte-string U))
                       (digest (kaesar-pbkdf2-tiny-hmac algorithm password bytes)))
                  (string-to-list digest))))
         (F (lambda (i)
              (cl-loop with U0 = (funcall PRF (append salt (kaesar-pbkdf2--pack 4 i)))
                       with Ux = U0
                       repeat (1- iter)
                       do (let ((U (funcall PRF U0)))
                            (setq Ux (kaesar-pbkdf2--logxor Ux U))
                            (setq U0 U))
                       finally return Ux)))
         (DK (lambda ()
               (cl-loop while (< (length result) size)
                        for i from 1
                        append (funcall F i) into result
                        finally return result))))

    (cl-loop for x in (funcall DK)
             repeat size
             collect x into key
             finally return key)))

(provide 'kaesar-pbkdf2)

;;; kaesar-pbkdf2.el ends here
