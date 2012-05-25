;;; cipher/aes-file.el --- Encrypt/Decrypt file with password.

;; Author: Masahiro Hayashi <mhayashi1120@gmail.com>
;; Keywords: encrypt decrypt file
;; URL: http://github.com/mhayashi1120/Emacs-cipher/raw/master/cipher/aes-file.el
;; Emacs: GNU Emacs 22 or later
;; Version 0.5.0

;;; Code:

(require 'cipher/aes)

;;;###autoload
(defun cipher/aes-encrypt-file (file)
  "Encrypt a FILE by `cipher/aes-algorithm'
which contents can be decrypted by `cipher/aes-decrypt-file-contents'."
  (with-temp-buffer
    (cipher/aes--insert-file-contents file)
    (let ((encrypted (cipher/aes-encrypt (buffer-string))))
      (erase-buffer)
      (insert encrypted)
      (cipher/aes--write-buffer file))))

;;;###autoload
(defun cipher/aes-decrypt-file (file &optional algorithm)
  "Decrypt a FILE contents with getting string.
FILE was encrypted by `cipher/aes-encrypt-file'."
  (with-temp-buffer
    (cipher/aes--insert-file-contents file)
    (let ((decrypted (cipher/aes-decrypt (buffer-string) algorithm)))
      (erase-buffer)
      (insert decrypted)
      (cipher/aes--write-buffer file))))

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

(defun cipher/aes--write-buffer (file)
  (cipher/aes--write-region (point-min) (point-max) file))

(defun cipher/aes--write-region (start end file)
  (let ((inhibit-file-name-handlers '(epa-file-handler))
        (inhibit-file-name-operation 'write-region)
        (coding-system-for-write 'binary))
    (write-region start end file nil 'no-msg)))

(defun cipher/aes--insert-file-contents (file)
  (let ((inhibit-file-name-handlers '(epa-file-handler))
        (inhibit-file-name-operation 'insert-file-contents)
        (coding-system-for-read 'binary))
    (insert-file-contents file)
    (set-buffer-multibyte nil)))

(provide 'cipher/aes-file)

;;; cipher/aes-file.el ends here
