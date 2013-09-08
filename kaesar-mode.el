;;; kaesar-mode.el --- Encrypt/Decrypt buffer by AES with password.

;; Author: Masahiro Hayashi <mhayashi1120@gmail.com>
;; Keywords: data, convenience
;; URL: https://github.com/mhayashi1120/Emacs-kaesar/raw/master/cipher/kaesar-mode.el
;; Emacs: GNU Emacs 22 or later
;; Version: 0.1.4
;; Package-Requires: ((kaesar "0.1.4"))

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

;; for testing purpose. DO NOT USE THIS normally.
(defvar kaesar-mode--test-password nil)

;;TODO http://epg.sourceforge.jp/
;; how to hide password more safely. consider:
;; 1. create internal password automatically. `kaesar-mode--volatile-password'
;; 2. above password never hold to variable otherwise clear immediately.
;; 3. volatile after emacs process is killed.
(defvar kaesar-mode--secure-password nil)
(make-variable-buffer-local 'kaesar-mode--secure-password)

(defvar kaesar-mode-algorithm nil)
(make-variable-buffer-local 'kaesar-mode-algorithm)

;; this variable only set when viewing kaesar-mode buffer as a binary.
(defvar kaesar-mode-meta-alist nil)
(put 'kaesar-mode-meta-alist 'safe-local-variable (lambda (_) t))

(defface kaesar-mode-lighter-face
  '((t (:inherit font-lock-warning-face)))
  "Face used for mode-line"
  :group 'kaesar-mode)

(defun kaesar-mode--encrypt (bytes algorithm)
  (let ((kaesar-password (kaesar-mode--password t)))
    (kaesar-encrypt-bytes bytes algorithm)))

(defun kaesar-mode--decrypt (bytes algorithm)
  (let ((kaesar-password (kaesar-mode--password nil)))
    (condition-case err
        (kaesar-decrypt-bytes bytes algorithm)
      (kaesar-decryption-failed
       ;; clear cached password if need
       (when (and kaesar-mode-cache-password
                  kaesar-mode--secure-password)
         (setq kaesar-mode--secure-password nil))
       (signal (car err) (cdr err))))))

(defun kaesar-mode--password (encrypt-p)
  (let ((prompt
         (if encrypt-p
             "Password to encrypt: "
           "Password to decrypt: ")))
    (cond
     (kaesar-mode--test-password
      (vconcat kaesar-mode--test-password))
     ((not kaesar-mode-cache-password)
      (read-passwd prompt encrypt-p))
     (kaesar-mode--secure-password
      (let ((kaesar-password (kaesar-mode--volatile-password)))
        (kaesar-decrypt-bytes kaesar-mode--secure-password)))
     (t
      (let ((pass (read-passwd prompt encrypt-p)))
        (setq kaesar-mode--secure-password
              (let ((kaesar-password (kaesar-mode--volatile-password)))
                (kaesar-encrypt-string pass)))
        pass)))))

;;TODO volatile password to suppress core file contains this.
;; TODO really volatile this value??
(defun kaesar-mode--volatile-password ()
  (string-as-unibyte
   (format "%s:%s:%s"
           (emacs-pid)
           (format-time-string "%s" after-init-time)
           (format-time-string "%s" before-init-time))))

(defun kaesar-mode--write-buffer ()
  (let* ((file buffer-file-name))
    (kaesar-mode--write-encrypt-data)
    (set-buffer-modified-p nil)
    (set-visited-file-modtime)
    (kaesar-mode--cleanup-backups file)
    (message (format "Wrote %s with kaesar encryption" file))))

(defun kaesar-mode--cleanup-backups (file)
  (loop for b in (find-backup-file-name file)
        do (when (and (file-exists-p b)
                      (eq (car (file-attributes b)) nil))
             (kaesar-mode--purge-file b))))

(defun kaesar-mode--purge-file (file)
  (let* ((size (nth 7 (file-attributes file)))
         (coding-system-for-write 'binary))
    (write-region (make-string size 0) nil file nil 'no-msg))
  (let ((delete-by-moving-to-trash nil))
    (delete-file file)))

(defun kaesar-mode--write-encrypt-data ()
  (let* ((file buffer-file-name)
         (text (buffer-string))
         (cs (or buffer-file-coding-system 'binary))
         (bytes (encode-coding-string text cs))
         (algorithm (or kaesar-mode-algorithm kaesar-algorithm))
         (encrypt/bytes (kaesar-mode--encrypt bytes algorithm))
         (mmode (let ((name (symbol-name major-mode)))
                  (and (string-match "-mode\\'" name)
                       major-mode)))
         (meta-info `((coding-system . ,cs)
                      (algorithm . ,algorithm)
                      (mode . ,mmode))))
    (with-temp-buffer
      (set-buffer-multibyte nil)
      (insert "##### -*- ")
      (insert "mode: kaesar; ")
      (insert "kaesar-mode-meta-alist: ")
      (insert (let ((print-escape-newlines t))
                (prin1-to-string meta-info)))
      (insert "; ")
      (insert "-*- \n")
      (insert encrypt/bytes)
      (let ((coding-system-for-write 'binary))
        (write-region (point-min) (point-max) file nil 'no-msg)))
    (setq last-coding-system-used cs)))

(defun kaesar-mode--read-encrypt-data (file)
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (let ((coding-system-for-write 'binary))
      (insert-file-contents file))
    (let* ((props (hack-local-variables-prop-line))
           (meta (assq 'kaesar-mode-meta-alist props)))
      ;; ignore first prop-line
      (goto-char (point-min))
      (forward-line 1)
      ;; handle `universal-coding-system-argument'
      (list (or coding-system-for-read
                (cdr (assq 'coding-system meta)))
            (cdr (assq 'algorithm meta))
            (cdr (assq 'mode meta))
            (buffer-substring-no-properties
             (point) (point-max))))))

;; re-open encrypted file
(defun kaesar-mode--decrypt-buffer ()
  (destructuring-bind (cs algorithm mode data)
      (kaesar-mode--read-encrypt-data buffer-file-name)
    (let* ((decrypt/bytes (kaesar-mode--decrypt data algorithm))
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
      (setq kaesar-mode-algorithm algorithm)
      (set-buffer-modified-p nil)
      (setq buffer-undo-list nil)
      (goto-char (point-min))
      ;;TODO should call interface function? 
      (when mode
        (with-demoted-errors
          (funcall mode))
        (unless kaesar-mode
          (kaesar-mode 1))))))

(defun kaesar-mode--file-guessed-encrypted-p (file)
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (let ((coding-system-for-read 'binary))
      ;; encrypted file must have Salted__ prefix and have at least one block.
      (insert-file-contents file nil 0 1024))
    (kaesar-mode--buffer-have-header-p)))

(defun kaesar-mode--buffer-have-header-p ()
  (save-excursion
    (save-restriction
      (widen)
      (goto-char (point-min))
      (looking-at "\\`##### -\\*-.* mode: *kaesar;"))))

(defun kaesar-mode-save-buffer ()
  (if (buffer-modified-p)
      (kaesar-mode--write-buffer)
    (message "(No changes need to be saved)"))
  ;; explicitly return non-nil
  t)

(defun kaesar-mode--revert-function ()
  (kaesar-mode 1))

(defun kaesar-mode-clear-cache-password ()
  (interactive)
  (unless (and kaesar-mode-cache-password
               kaesar-mode--secure-password)
    (error "No need to explicitly clear the password"))
  (setq kaesar-mode--secure-password nil)
  (set-buffer-modified-p t))

;; `find-file-noselect' -> `normal-mode' -> `set-auto-mode'

;;;###autoload
(define-minor-mode kaesar-mode
  "Automatically encrypt buffer with password.
todo about header which prepend by `kaesar-mode'
todo how to grep encrypt file
todo `kaesar-mode-cache-password'
 "
  :init-value nil
  :lighter (" [" (:propertize "KaesarEncrypt" face kaesar-mode-lighter-face) "]")
  :group 'kaesar-mode
  ;; Suppress two time `kaeasr-mode' call.
  ;; `normal-mode': `set-auto-mode' -> `hack-local-variables'
  (add-hook 'before-hack-local-variables-hook
            (lambda ()
              (setq file-local-variables-alist
                    (assq-delete-all 'mode file-local-variables-alist)))
            nil t)
  (cond
   ((not buffer-file-name)
    (message "Buffer has no physical file.")
    (kaesar-mode -1))
   ((not kaesar-mode)
    (remove-hook 'write-contents-functions 'kaesar-mode-save-buffer t)
    (remove-hook 'after-revert-hook 'kaesar-mode--revert-function t)
    (kill-local-variable 'kaesar-mode-algorithm)
    (when (and (kaesar-mode--file-guessed-encrypted-p buffer-file-name)
               (not (kaesar-mode--buffer-have-header-p)))
      ;; trick to execute `basic-save-buffer'
      (set-buffer-modified-p t)
      (basic-save-buffer)))
   (t
    (make-local-variable 'kaesar-mode-algorithm)
    (unless (kaesar-mode--file-guessed-encrypted-p buffer-file-name)
      ;; first time call `kaesar-mode'
      (kaesar-mode--write-buffer))
    (when (kaesar-mode--buffer-have-header-p)
      (let ((done nil))
        (condition-case quit
            (while (not done)
              (condition-case err
                  (progn
                    (kaesar-mode--decrypt-buffer)
                    (setq done t))
                (kaesar-decryption-failed
                 (message "Password wrong!")
                 (sit-for 1))
                (error
                 (kaesar-mode -1)
                 (signal (car err) (cdr err)))))
          (quit
           (kaesar-mode -1)))))
    (when kaesar-mode
      (add-hook 'write-contents-functions 'kaesar-mode-save-buffer nil t)
      (add-hook 'after-revert-hook 'kaesar-mode--revert-function nil t)))))

(provide 'kaesar-mode)

;;; kaesar-mode.el ends here
