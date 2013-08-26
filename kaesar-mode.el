;;; kaesar-mode.el --- Encrypt/Decrypt buffer by AES with password.

;; Author: Masahiro Hayashi <mhayashi1120@gmail.com>
;; Keywords: data, convenience
;; URL: https://github.com/mhayashi1120/Emacs-kaesar/raw/master/cipher/kaesar-mode.el
;; Emacs: GNU Emacs 22 or later
;; Version: 0.1.2
;; Package-Requires: ((kaesar "0.1.1"))

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
;;     (require 'kaesar-mode)

;;; Usage:

;; This package intention to `enable-local-variables' as default value `t'
;; If you change this variable to `nil' then you must execute M-x kaesar-mode
;; explicitly.

;;; Code:

(eval-when-compile
  (require 'cl))

(require 'kaesar)

(defgroup kaesar-mode nil
  "Handling buffer with AES cipher."
  :group 'kaesar
  :prefix "kaesar-mode-")

(defcustom kaesar-mode-cache-password nil
  "This variable control password cache for each editing buffer."
  :group 'kaesar-mode
  :type 'boolean)

;; for testing purpose. do not use this normally.
(defvar kaesar-mode--test-password nil)

;;TODO http://epg.sourceforge.jp/
;; how to hide password more safely. consider:
;; 1. create internal password automatically. `kaesar-mode--volatile-password'
;; 2. above password never hold to variable otherwise clear immediately.
;; 3. volatile after emacs process will be dead.
(defvar kaesar-mode--secure-password nil)
(make-variable-buffer-local 'kaesar-mode--secure-password)

;; using only pseudo prop-line.
;; when decrypting fails, this will be a buffer local variable.
(defvar kaesar-mode-coding-system nil)
(put 'kaesar-mode-coding-system 'safe-local-variable (lambda (_) t))

(defconst kaesar-mode--encrypt-body-regexp
  (concat "^" (regexp-quote kaesar--openssl-magic-word)))

(defface kaesar-mode-lighter-face
  '((t (:inherit font-lock-warning-face)))
  "Face used for mode-line"
  :group 'kaesar-mode)


;;;###autoload
(define-minor-mode kaesar-mode
  "TODO
Handling buffer with file encryption by password.
todo about header
todo how to grep
 "
  :init-value nil
  :lighter (" [" (:propertize "KaesarEncrypt" face kaesar-mode-lighter-face) "]")
  :group 'kaesar-mode
  (cond
   ((not buffer-file-name)
    (message "Buffer has no physical file.")
    (kaesar-mode -1))
   ((not kaesar-mode)
    (remove-hook 'write-contents-functions 'kaesar-mode-save-buffer t)
    (remove-hook 'after-revert-hook 'kaesar-mode--revert-function t)
    (when (kaesar-mode--file-guessed-encrypted-p buffer-file-name)
      ;; trick to execute `basic-save-buffer'
      (set-buffer-modified-p t)
      (basic-save-buffer)))
   (t
    (if (not (kaesar-mode--file-guessed-encrypted-p buffer-file-name))
        ;; first time call `kaesar-mode'
        (kaesar-mode--write-buffer)
      ;; when open already decrypted file.
      (kaesar-mode--decrypt-buffer))
    (add-hook 'write-contents-functions 'kaesar-mode-save-buffer nil t)
    (add-hook 'after-revert-hook 'kaesar-mode--revert-function nil t))))

(defun kaesar-mode-save-buffer ()
  (if (buffer-modified-p)
      (kaesar-mode--write-buffer)
    (message "(No changes need to be saved)"))
  ;; explicitly return non-nil
  t)

(defun kaesar-mode--revert-function ()
  (kaesar-mode 1))

(defun kaesar-mode--encrypt (bytes)
  (let ((kaesar-password (kaesar-mode--password t)))
    (kaesar-encrypt-bytes bytes)))

(defun kaesar-mode--decrypt (bytes)
  (let ((kaesar-password (kaesar-mode--password nil)))
    (condition-case err
        (kaesar-decrypt-bytes bytes)
      (kaesar-decryption-failed
       ;; clear cached password if need
       (when (and kaesar-mode-cache-password
                  kaesar-mode--secure-password)
         (setq kaesar-mode--secure-password nil))
       (signal (car err) (cdr err))))))

(defun kaesar-mode--password (confirm)
  (cond
   (kaesar-mode--test-password
    (vconcat kaesar-mode--test-password))
   ((not kaesar-mode-cache-password)
    (read-passwd "Password: " confirm))
   (kaesar-mode--secure-password
    (let ((kaesar-password (kaesar-mode--volatile-password)))
      (kaesar-decrypt-bytes kaesar-mode--secure-password)))
   (t
    (let ((pass (read-passwd "Password: " confirm)))
      (setq kaesar-mode--secure-password
            (let ((kaesar-password (kaesar-mode--volatile-password)))
              (kaesar-encrypt-string pass)))
      pass))))

;;TODO volatile password to suppress core file contains this.
;; TODO really volatile this value??
(defun kaesar-mode--volatile-password ()
  (string-as-unibyte
   (format "%s:%s:%s"
           (emacs-pid)
           (format-time-string "%s" after-init-time)
           (format-time-string "%s" before-init-time))))

(defun kaesar-mode--write-buffer ()
  (let* ((file buffer-file-name)
         (text (buffer-string))
         (cs (or buffer-file-coding-system 'utf-8))
         (bytes (encode-coding-string text cs)))
    (let ((meta `((kaesar-mode-coding-system . ,cs))))
      (kaesar-mode--write-encrypt-data file bytes meta)
      (set-buffer-modified-p nil)
      (set-visited-file-modtime)
      (setq last-coding-system-used cs)
      (kaesar-mode--cleanup-backups file)
      (message (format "Wrote %s with kaesar encryption" file)))))

(defun kaesar-mode--cleanup-backups (file)
  (loop for b in (find-backup-file-name file)
        do (when (and (file-exists-p b)
                      (eq (car (file-attributes b)) nil))
             (kaesar-file--purge-file b))))

(defun kaesar-file--purge-file (file)
  (let ((size (nth 7 (file-attributes file))))
    (let ((coding-system-for-write 'binary))
      (write-region (make-string size 0) nil file nil 'no-msg))
    (let ((delete-by-moving-to-trash nil))
      (delete-file file))))

(defun kaesar-mode--write-encrypt-data (file bytes meta-info)
  (let ((encrypt/bytes (kaesar-mode--encrypt bytes)))
    (with-temp-buffer
      (set-buffer-multibyte nil)
      (insert "##### -*- ")
      (insert "mode: kaesar; ")
      (dolist (i meta-info)
        ;; like local variable prop-line section
        (let ((section (format "%s: %s; " (car i) (cdr i))))
          (insert section)))
      (insert "-*- \n")
      (insert encrypt/bytes)
      (let ((coding-system-for-write 'binary))
        (write-region (point-min) (point-max) file nil 'no-msg)))))

(defun kaesar-mode--read-encrypt-data (file)
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (let ((coding-system-for-write 'binary))
      (insert-file-contents file))
    (let ((props (hack-local-variables-prop-line)))
      ;; ignore first prop-line
      (goto-char (point-min))
      (forward-line 1)
      ;; handle `universal-coding-system-argument'
      (list (or coding-system-for-read
                (cdr (assq 'kaesar-mode-coding-system props)))
            (buffer-substring-no-properties
             (point) (point-max))))))

;; re-open encrypted file
(defun kaesar-mode--decrypt-buffer ()
  (destructuring-bind (cs data)
      (kaesar-mode--read-encrypt-data buffer-file-name)
    (let* ((decrypt/bytes (kaesar-mode--decrypt data))
           (contents
            (if cs
                (decode-coding-string decrypt/bytes cs)
              decrypt/bytes)))
      (let ((inhibit-read-only t)
            buffer-read-only)
        (erase-buffer)
        (when (multibyte-string-p contents)
          (set-buffer-multibyte t))
        (insert contents)
        (setq buffer-file-coding-system cs))
      (kaesar-mode--buffer-hack-after-decrypt)
      (set-buffer-modified-p nil)
      (setq buffer-undo-list nil)
      (goto-char (point-min)))))

(defun kaesar-mode--buffer-hack-after-decrypt ()
  (hack-local-variables)
  ;; Since save-buffer() is not used, we don't have to take care of
  ;; make-backup-files
  (auto-save-mode -1))

(defun kaesar-mode--file-guessed-encrypted-p (file)
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (let ((coding-system-for-read 'binary))
      ;; encrypted file must have Salted__ prefix and have at least one block.
      (insert-file-contents file nil 0 256))
    (goto-char (point-min))
    (and (looking-at "\\`##### -\\*-.* mode: *kaesar;")
         (progn
           (forward-line 1)
           (looking-at kaesar-mode--encrypt-body-regexp)))))

(provide 'kaesar-mode)

;;; kaesar-mode.el ends here
