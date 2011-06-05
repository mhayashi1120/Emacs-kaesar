;;; aes-mode.el --- Encrypt/Decrypt string with password.

;; Author: Masahiro Hayashi <mhayashi1120@gmail.com>
;; Keywords: encrypt decrypt password Rijndael
;; URL: http://github.com/mhayashi1120/Emacs-cipher/raw/master/cipher/aes-mode.el
;; Emacs: GNU Emacs 22 or later
;; Version 0.5.0

(defconst aes-mode-version "0.5.0")

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
;;     (require 'aes-mode)

;;; Usage:

;; TODO

;;; Code:

(eval-when-compile
  (require 'cl))

(require 'cipher/aes)

(defgroup aes-mode nil
  "AES cipher User Interface.")

(defvar aes-mode-map nil)

(let ((map (or aes-mode-map (make-sparse-keymap))))
  (define-key map "\C-x\C-s" 'aes-mode-save-buffer)
  (setq aes-mode-map map))

(define-minor-mode aes-mode
  "TODO"
  :init-value nil
  :lighter " AES" 
  :keymap aes-mode-map
  :group 'aes-mode
  (when aes-mode
    (cond
     ((aes-mode--buffer-guessed-encrypted-p)
      (condition-case err
          (aes-mode--visit-again)
        (error 
         ;; disable the mode
         (aes-mode -1)
         (signal (car err) (cdr err)))))
     ((not (aes-mode--file-guessed-encrypted-p))
      (aes-mode--write-buffer)))
    ;;TODO no effect?
    (add-hook 'after-revert-hook 'aes-mode--revert-function nil t))
  (unless aes-mode
    (remove-hook 'after-revert-hook 'aes-mode--revert-function t)))

(define-globalized-minor-mode aes-global-mode
  aes-mode aes-mode-maybe
  :group 'aes-mode)

(defun aes-mode-save-buffer ()
  "TODO"
  (interactive)
  (if (buffer-modified-p)
      (aes-mode--write-buffer)
    (message "(No changes need to be saved)")))

(defun aes-mode--revert-function ()
  (aes-mode 1))

(defun aes-mode-maybe ()
  (when (and (not (minibufferp))
             (not aes-mode)
             (aes-mode--guessed-encrypted-p))
    (aes-mode 1)))

(defun aes-mode--write-buffer ()
  (let* ((file (buffer-file-name))
         (meta (aes-mode--serialize-local-variables))
         (contents (encode-coding-string (buffer-string) buffer-file-coding-system))
         (bytes (vconcat meta contents)))
    (unwind-protect
        (progn
          (let ((coding-system-for-write 'binary))
            (write-region (aes-mode--encrypt bytes) nil file nil 'no-msg))
          (set-buffer-modified-p nil)
          (set-visited-file-modtime)
          (message (format "Wrote %s with AES encryption" file)))
      ;; clean up backup files if exists.
      (loop for b in (find-backup-file-name file)
            do (when (and (file-exists-p b)
                          (eq (car (file-attributes b)) nil))
                 (delete-file b))))))

(defun aes-mode--encrypt (bytes)
  (let ((aes-password (aes-mode--password t)))
    (aes-encrypt bytes)))

(defun aes-mode--decrypt (bytes)
  (let ((aes-password (aes-mode--password nil)))
    (aes-decrypt bytes)))

(defun aes-mode--password (confirm)
  (and aes-mode-cache-password
       (progn
         (unless aes-mode-password
           (setq aes-mode-password
                 (aes--read-passwd "Password: ")))
         (vconcat aes-mode-password))))

;; re-open encrypted file
(defun aes-mode--visit-again ()
  (let* ((file (buffer-file-name))
         (data (with-temp-buffer
                 (set-buffer-multibyte nil)
                 (let ((coding-system-for-write 'binary))
                   (insert-file-contents file))
                 (buffer-string))))
    (destructuring-bind (meta contents)
        (let* ((decrypted (aes-mode--decrypt data))
               (first-read (read-from-string decrypted)))
          ;;TODO undecided coding-system `universal-coding-system-argument'
          (list (car first-read) (decode-coding-string (substring decrypted (cdr first-read)) 'undecided)))
      (let ((inhibit-read-only t)
            buffer-read-only)
        (erase-buffer)
        (when (default-value 'enable-multibyte-characters)
          (set-buffer-multibyte t))
        (insert contents))
      (aes-mode--buffer-hack)
      (aes-mode--deserialize-local-variables meta)
      (set-buffer-modified-p nil)
      (setq buffer-undo-list nil)))
  (goto-char (point-min)))

(defun aes-mode--buffer-hack ()
  (hack-local-variables)
  ;; Since save-buffer() is not used, we don't have to take care of
  ;; make-backup-files
  (auto-save-mode nil))

(defconst aes-mode--salted-regexp 
  (format "^%s\\(\\(?:.\\|\n\\)\\{16\\}\\)" cipher/aes--openssl-magic-word))

(defconst aes-mode--block-size
  (* cipher/aes--Nb cipher/aes--Row))

;;TODO
(defvar aes-mode-cache-password nil)
(defvar aes-mode-password nil)

(make-variable-buffer-local 'aes-mode-password)

(defun aes-mode--guessed-encrypted-p ()
  (and 
   ;;TODO FIXME suppress two time password prompt
   ;;     globalized minor mode make these conduct.
   (aes-mode--buffer-guessed-encrypted-p)
   (aes-mode--file-guessed-encrypted-p)))

(defun aes-mode--buffer-guessed-encrypted-p ()
  (save-excursion
    (save-restriction
      (widen)
      (goto-char (point-min))
      (looking-at cipher/aes--openssl-magic-word))))

(defun aes-mode--file-guessed-encrypted-p ()
  (and buffer-file-name
       (let ((size (nth 7 (file-attributes buffer-file-name))))
         (and (integerp size)
              (>= size (* aes-mode--block-size 2))
              (= (mod size aes-mode--block-size) 0)))
       (let ((file buffer-file-name))
         (with-temp-buffer
           (set-buffer-multibyte nil)
           (let ((coding-system-for-read 'binary))
             ;; encrypted file must have Salted__ prefix and at least one block.
             (insert-file-contents file nil 0 (* aes-mode--block-size 2)))
           (goto-char (point-min))
           (and (looking-at aes-mode--salted-regexp)
                (let ((bin-salt (match-string 1)))
                  ;; Most of encrypted file have 8 bit char at top of 32 byte.
                  (string-match "[\200-\377]" bin-salt)))))))

(defvar aes-mode-local-variables
  '( 
    (buffer-file-coding-system . set-buffer-file-coding-system)
    ))

(defun aes-mode--deserialize-local-variables (alist)
  (mapc
   (lambda (pair)
     (let ((settings (assq (car pair) aes-mode-local-variables)))
       (cond
        ((and (cdr settings)
              (functionp (cdr settings)))
         (funcall (cdr settings) (cdr pair)))
        ((or (null settings)
             (null (cdr settings)))
         (set (car pair) (cdr pair))))))
   alist))

(defun aes-mode--serialize-local-variables ()
  (let ((string (prin1-to-string
                 (remove nil
                         (mapcar
                          (lambda (pair)
                            (let ((v (car pair)))
                              (when (and (boundp v)
                                         (local-variable-p v))
                                (cons v (symbol-value v)))))
                          aes-mode-local-variables)))))
    (vconcat (string-make-unibyte string))))

(provide 'aes-mode)

;;; aes-mode.el ends here
