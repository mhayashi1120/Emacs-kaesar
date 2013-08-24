;;; kaesar-mode.el --- Encrypt/Decrypt string with password.

;; Author: Masahiro Hayashi <mhayashi1120@gmail.com>
;; Keywords: data, convenience
;; URL: https://github.com/mhayashi1120/Emacs-kaesar/raw/master/cipher/kaesar-mode.el
;; Emacs: GNU Emacs 22 or later
;; Version: 0.1.0
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
;;     (require 'kaesar-mode)

;;; Usage:

;; TODO
;; * revert-buffer
;; * ert test

;;; Code:

(eval-when-compile
  (require 'cl))

(require 'kaesar)

(defgroup kaesar-mode nil
  "AES cipher User Interface."
  :group 'kaesar
  :prefix "kaesar-mode-")

(defvar kaesar-mode-map nil)

(let ((map (or kaesar-mode-map (make-sparse-keymap))))
  ;;TODO remap? local-write-file-hooks?
  (define-key map "\C-x\C-s" 'kaesar-mode-save-buffer)
  (setq kaesar-mode-map map))

;;;###autoload
(define-minor-mode kaesar-mode
  "TODO"
  :init-value nil
  :lighter " AES" 
  :keymap kaesar-mode-map
  :group 'kaesar-mode
  (cond
   ((not kaesar-mode))
   ((kaesar-mode--buffer-guessed-encrypted-p)
    (condition-case err
        (kaesar-mode--visit-again)
      (error 
       ;; disable the mode
       (kaesar-mode -1)
       (signal (car err) (cdr err)))))
   ((not (kaesar-mode--file-guessed-encrypted-p))
    (kaesar-mode--write-buffer)))
  ;;TODO no effect?
  (add-hook 'after-revert-hook 'kaesar-mode--revert-function nil t)
  (unless kaesar-mode
    (remove-hook 'after-revert-hook 'kaesar-mode--revert-function t)))

;;;###autoload
(define-globalized-minor-mode kaesar-global-mode
  kaesar-mode kaesar-mode-maybe
  :group 'kaesar-mode)

(defun kaesar-mode-save-buffer ()
  "TODO"
  (interactive)
  (if (buffer-modified-p)
      (kaesar-mode--write-buffer)
    (message "(No changes need to be saved)")))

(defun kaesar-mode--revert-function ()
  (kaesar-mode 1))

(defun kaesar-mode-maybe ()
  (when (and (not (minibufferp))
             (not kaesar-mode)
             (kaesar-mode--guessed-encrypted-p))
    (kaesar-mode 1)))

(defun kaesar-mode--write-buffer ()
  (let* ((file (buffer-file-name))
         (meta (kaesar-mode--serialize-local-variables))
         (contents (encode-coding-string (buffer-string) buffer-file-coding-system))
         (bytes (vconcat meta contents)))
    (unwind-protect
        (progn
          (let ((coding-system-for-write 'binary))
            (write-region (kaesar-mode--encrypt bytes) nil file nil 'no-msg))
          (set-buffer-modified-p nil)
          (set-visited-file-modtime)
          (message (format "Wrote %s with kaesar encryption" file)))
      ;; clean up backup files if exists.
      (loop for b in (find-backup-file-name file)
            do (when (and (file-exists-p b)
                          (eq (car (file-attributes b)) nil))
                 (let ((delete-by-moving-to-trash nil))
                   (delete-file b)))))))

(defun kaesar-mode--encrypt (bytes)
  (let ((kaesar-password (kaesar-mode--password t)))
    (kaesar-encrypt-bytes bytes)))

(defun kaesar-mode--decrypt (bytes)
  (let ((kaesar-password (kaesar-mode--password nil)))
    (kaesar-decrypt-bytes bytes)))

(defun kaesar-mode--password (confirm)
  (and kaesar-mode-cache-password
       (progn
         (unless kaesar-mode-password
           (setq kaesar-mode-password
                 (kaesar--read-passwd "Password: ")))
         (vconcat kaesar-mode-password))))

;; re-open encrypted file
(defun kaesar-mode--visit-again ()
  (let* ((file (buffer-file-name))
         (data (with-temp-buffer
                 (set-buffer-multibyte nil)
                 (let ((coding-system-for-write 'binary))
                   (insert-file-contents file))
                 (buffer-string))))
    (destructuring-bind (meta contents)
        (let* ((decrypted (kaesar-mode--decrypt data))
               (first-read (read-from-string decrypted)))
          ;;TODO undecided coding-system `universal-coding-system-argument'
          (list (car first-read) (decode-coding-string (substring decrypted (cdr first-read)) 'undecided)))
      (let ((inhibit-read-only t)
            buffer-read-only)
        (erase-buffer)
        (when (default-value 'enable-multibyte-characters)
          (set-buffer-multibyte t))
        (insert contents))
      (kaesar-mode--buffer-hack)
      (kaesar-mode--deserialize-local-variables meta)
      (set-buffer-modified-p nil)
      (setq buffer-undo-list nil)))
  (goto-char (point-min)))

(defun kaesar-mode--buffer-hack ()
  (hack-local-variables)
  ;; Since save-buffer() is not used, we don't have to take care of
  ;; make-backup-files
  (auto-save-mode nil))

(defconst kaesar-mode--salted-regexp 
  (format "^%s\\(\\(?:.\\|\n\\)\\{16\\}\\)" kaesar--openssl-magic-word))

(defconst kaesar-mode--block-size
  (* kaesar--Nb kaesar--Row))

;;TODO
(defvar kaesar-mode-cache-password nil)
(defvar kaesar-mode-password nil)

(make-variable-buffer-local 'kaesar-mode-password)

(defun kaesar-mode--guessed-encrypted-p ()
  (and 
   ;;TODO FIXME suppress two time password prompt
   ;;     globalized minor mode make these conduct.
   (kaesar-mode--buffer-guessed-encrypted-p)
   (kaesar-mode--file-guessed-encrypted-p)))

(defun kaesar-mode--buffer-guessed-encrypted-p ()
  (save-excursion
    (save-restriction
      (widen)
      (goto-char (point-min))
      (looking-at kaesar--openssl-magic-word))))

(defun kaesar-mode--file-guessed-encrypted-p ()
  (and buffer-file-name
       (let ((size (nth 7 (file-attributes buffer-file-name))))
         (and (integerp size)
              (>= size (* kaesar-mode--block-size 2))
              (= (mod size kaesar-mode--block-size) 0)))
       (let ((file buffer-file-name))
         (with-temp-buffer
           (set-buffer-multibyte nil)
           (let ((coding-system-for-read 'binary))
             ;; encrypted file must have Salted__ prefix and have at least one block.
             (insert-file-contents file nil 0 (* kaesar-mode--block-size 2)))
           (goto-char (point-min))
           (and (looking-at kaesar-mode--salted-regexp)
                (let ((bin-salt (match-string 1)))
                  ;; Most of encrypted file have 8 bit char at top of 32 byte.
                  (string-match "[\200-\377]" bin-salt)))))))

(defvar kaesar-mode-local-variables
  '( 
    (buffer-file-coding-system . set-buffer-file-coding-system)
    ))

(defun kaesar-mode--deserialize-local-variables (alist)
  (mapc
   (lambda (pair)
     (let ((settings (assq (car pair) kaesar-mode-local-variables)))
       (cond
        ((and (cdr settings)
              (functionp (cdr settings)))
         (funcall (cdr settings) (cdr pair)))
        ((or (null settings)
             (null (cdr settings)))
         (set (car pair) (cdr pair))))))
   alist))

(defun kaesar-mode--serialize-local-variables ()
  (let ((string (prin1-to-string
                 (remove nil
                         (mapcar
                          (lambda (pair)
                            (let ((v (car pair)))
                              (when (and (boundp v)
                                         (local-variable-p v))
                                (cons v (symbol-value v)))))
                          kaesar-mode-local-variables)))))
    (vconcat (string-make-unibyte string))))

(provide 'kaesar-mode)

;;; kaesar-mode.el ends here
