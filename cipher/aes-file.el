;;; cipher/aes-file.el --- Encrypt/Decrypt file with password.

;; Author: Masahiro Hayashi <mhayashi1120@gmail.com>
;; Keywords: encrypt decrypt file
;; URL: http://github.com/mhayashi1120/Emacs-cipher/raw/master/cipher/aes-file.el
;; Emacs: GNU Emacs 22 or later
;; Version 0.6.0

;;; Code:

(require 'cipher/aes)

;;;###autoload
(defun cipher/aes-encrypt-file (file &optional algorithm with-base64 save-file)
  "Encrypt a FILE by `cipher/aes-algorithm'
which contents can be decrypted by `cipher/aes-decrypt-file-contents'."
  (with-temp-buffer
    (cipher/aes--insert-file-contents file)
    (let ((encrypted (cipher/aes-encrypt (buffer-string) algorithm)))
      (erase-buffer)
      (cond
       (with-base64
        (cipher/aes-prepare-base64
         encrypted (or algorithm cipher/aes-algorithm)))
       (t
        (insert encrypted)))
      (cipher/aes--write-buffer (or save-file file)))))

;;;###autoload
(defun cipher/aes-decrypt-file (file &optional algorithm save-file)
  "Decrypt a FILE contents with getting string.
FILE was encrypted by `cipher/aes-encrypt-file'."
  (with-temp-buffer
    (cipher/aes--insert-file-contents file)
    (let* ((enc-algo (cipher/aes-decode-if-base64))
           (decrypted
            (cipher/aes-decrypt
             (buffer-string) (or algorithm enc-algo))))
      (erase-buffer)
      (insert decrypted)
      (cipher/aes--write-buffer (or save-file file)))))

;;;###autoload
(defun cipher/aes-decrypt-file-contents (file &optional algorithm coding-system)
  "Decrypt a FILE contents with getting string.
FILE was encrypted by `cipher/aes-encrypt-file'."
  (with-temp-buffer
    (cipher/aes--insert-file-contents file)
    (let ((decrypted (cipher/aes-decrypt (buffer-string) algorithm)))
      (if coding-system
          (decode-coding-string decrypted coding-system)
        decrypted))))

;;;###autoload
(defun cipher/aes-encrypt-write-region (start end file)
  "Write START END region to FILE with encryption."
  (interactive "r\nF")
  (let* ((str (buffer-substring start end))
         (cs (or buffer-file-coding-system default-terminal-coding-system))
         (s (encode-coding-string str cs))
         (encrypted (cipher/aes-encrypt s)))
    (cipher/aes--write-region encrypted nil file)))

(defun cipher/aes-prepare-base64 (encrypted-data algorithm)
  (insert "-----BEGIN ENCRYPTED DATA-----\n")
  (insert (format "Algorithm: %s\n" algorithm))
  (insert "\n")
  (insert (base64-encode-string encrypted-data) "\n")
  (insert "-----END ENCRYPTED DATA-----\n"))

(defun cipher/aes-decode-if-base64 ()
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

(defun cipher/aes--write-buffer (file)
  (cipher/aes--write-region (point-min) (point-max) file))

(defun cipher/aes--write-region (start end file)
  ;; to suppress two time encryption
  (let ((inhibit-file-name-handlers '(epa-file-handler))
        (inhibit-file-name-operation 'write-region)
        (coding-system-for-write 'binary))
    (write-region start end file nil 'no-msg)))

(defun cipher/aes--insert-file-contents (file)
  ;; to suppress two time decryption
  (let ((inhibit-file-name-handlers '(epa-file-handler))
        (inhibit-file-name-operation 'insert-file-contents)
        (coding-system-for-read 'binary))
    (insert-file-contents file)
    (set-buffer-multibyte nil)))

(provide 'cipher/aes-file)

;;; cipher/aes-file.el ends here
