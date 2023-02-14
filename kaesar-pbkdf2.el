;;; kaesar-pbkdf2.el --- kaesar.el PBKDF2 extension -*- lexical-binding: t -*-

;; Author: Masahiro Hayashi <mhayashi1120@gmail.com>
;; Keywords: data
;; URL: https://github.com/mhayashi1120/Emacs-kaesar
;; Emacs: GNU Emacs 24.3 or later
;; Version: 0.9.0
;; Package-Requires: ((emacs "24.3") (kaesar "0.9.5") (hmac "1.0"))

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

;; TODO
;; PBKDF2 is `Password-Based Key Derivation Function 2`

;;; Code:

(require 'cl-lib)

(defun kaesar-pbkdf2--pack (size n)
  (cl-loop repeat size
           for i from 0
           collect (logand (ash n (* i -8)) #xff) into r
           finally return (nreverse r)))

(defun kaesar-pbkdf2--logxor (u1 u2)
  (cl-mapcar
   (lambda (b1 b2) (logxor b1 b2))
   u1 u2))

;; TODO
(defun check-natural (x &rest _))

(defun kaesar-pbkdf2-hmac (password iter size &optional salt algorithm)
  (check-natural iter 1)
  (check-natural size 1)
  (setq algorithm (or algorithm 'sha256))
  (setq salt (or salt ()))
  (let* ((PRF (lambda (U)
                (let ((digest (hmac algorithm password (apply 'unibyte-string U) t)))
                  (string-to-list digest))))
         (F (lambda (i)
              (cl-loop with Ux = (funcall PRF (append salt (kaesar-pbkdf2--pack 4 i)))
                       repeat (1- iter)
                       do (setq Ux (kaesar-pbkdf2--logxor Ux (funcall PRF Ux)))
                       finally return Ux)))
         (DK (lambda ()
               (cl-loop while (< (length result) size)
                        for i from 1
                        append (funcall F i) into result
                        finally return result))))

    (cl-loop for x in (funcall DK)
             repeat size
             collect x)))

(provide 'kaesar-pbkdf2)

;;; kaesar-pbkdf2.el ends here
