;;; kaesar-file.el --- Encrypt/Decrypt file with password.

;; Author: Masahiro Hayashi <mhayashi1120@gmail.com>
;; Keywords: data, files
;; URL: https://github.com/mhayashi1120/Emacs-kaesar/raw/master/cipher/kaesar-file.el
;; Emacs: GNU Emacs 22 or later
;; Version: 0.5.0
;; Package-Requires: ((kaesar "0.1.0"))

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

;; Put this file into load-path'ed directory, and byte compile it if
;; desired. And put the following expression into your ~/.emacs.
;;
;;     (require 'kaesar-file)

;;; Usage:

;; TODO

;;; Code:

(require 'kaesar)

(defgroup 'kaesar-file ()
  :prefix "kaesar-file-"
  :gruop 'kaesar)

(defun kaesar-file--prepare-base64 (algorithm)
  (insert "-----BEGIN ENCRYPTED DATA-----\n")
  (insert (format "Algorithm: %s\n" algorithm))
  (insert "\n")
  (base64-encode-region (point-min) (point-max))
  (insert  "\n")
  (insert "-----END ENCRYPTED DATA-----\n"))

(defun kaesar-file--decode-if-base64 ()
  ;; decode buffer if valid base64 encoded.
  ;; return a algorithm of encryption.
  (let (algorithm)
    (goto-char (point-min))
    (when (re-search-forward "^-----BEGIN ENCRYPTED DATA" nil t)
      (when (re-search-forward "^Algorithm: \\(.*\\)" nil t)
        (setq algorithm (match-string 1))
        ;; delete base64 header
        (delete-region (point-min) (line-beginning-position 2)))
      (when (re-search-forward "^-----END ENCRYPTED DATA" nil t)
        ;; delete base64 footer
        (delete-region (line-beginning-position) (line-end-position)))
      (base64-decode-region (point-min) (point-max)))
    algorithm))

(defun kaesar--write-buffer (file)
  (kaesar--write-region (point-min) (point-max) file))

(defun kaesar--write-region (start end file)
  ;; to suppress two time encryption
  (let ((inhibit-file-name-handlers '(epa-file-handler))
        (inhibit-file-name-operation 'write-region)
        (coding-system-for-write 'binary)
        (jka-compr-compression-info-list nil))
    (write-region start end file nil 'no-msg)))

(defun kaesar--insert-file-contents (file)
  ;; to suppress two time decryption
  (let ((format-alist nil)
        (after-insert-file-functions nil)
        (jka-compr-compression-info-list nil)
        (inhibit-file-name-handlers '(epa-file-handler))
        (inhibit-file-name-operation 'insert-file-contents)
        (coding-system-for-read 'binary))
    (insert-file-contents file)
    (set-buffer-multibyte nil)))

;;TODO consider interface

;;;###autoload
(defun kaesar-encrypt-file (file &optional algorithm mode save-file)
  "Encrypt a FILE by `kaesar-algorithm'
which contents can be decrypted by `kaesar-decrypt-file-contents'.

MODE: TODO
"
  (with-temp-buffer
    (kaesar--insert-file-contents file)
    (let ((encrypted (kaesar-encrypt-bytes (buffer-string) algorithm)))
      (erase-buffer)
      (insert encrypted)
      (cond
       ((or (null mode) (eq mode 'binary)))
       ((eq mode 'base64-with-header)
        (kaesar-file--prepare-base64 (or algorithm kaesar-algorithm)))
       ((eq mode 'base64)
        (base64-decode-region (point-min) (point-max)))
       (t
        ;;TODO
        (error "Not a supported mode %s" mode)))
      (kaesar--write-buffer (or save-file file)))))

;;;###autoload
(defun kaesar-decrypt-file (file &optional algorithm save-file)
  "Decrypt a FILE contents with getting string.
FILE was encrypted by `kaesar-encrypt-file'."
  (with-temp-buffer
    (kaesar--insert-file-contents file)
    (let* ((enc-algo (kaesar-file--decode-if-base64))
           (decrypted
            (kaesar-decrypt-bytes
             (buffer-string)
             (or algorithm enc-algo kaesar-algorithm))))
      (erase-buffer)
      (insert decrypted)
      (kaesar--write-buffer (or save-file file)))))

;;;###autoload
(defun kaesar-decrypt-file-contents (file &optional algorithm coding-system)
  "Decrypt a FILE contents with getting string.
FILE was encrypted by `kaesar-encrypt-file'."
  (with-temp-buffer
    (kaesar--insert-file-contents file)
    (let ((decrypted (kaesar-decrypt-bytes (buffer-string) algorithm)))
      (if coding-system
          (decode-coding-string decrypted coding-system)
        decrypted))))

;;;###autoload
(defun kaesar-encrypt-write-region (start end file)
  "Write START END region to FILE with encryption."
  (interactive "r\nF")
  (let* ((str (buffer-substring start end))
         (cs (or buffer-file-coding-system default-terminal-coding-system))
         (s (encode-coding-string str cs))
         (encrypted (kaesar-encrypt-bytes s)))
    (kaesar--write-region encrypted nil file)))

(provide 'kaesar-file)

;;; kaesar-file.el ends here
