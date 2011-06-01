
(defvar aes-demo--rest-of-decoded nil)
(defvar aes-demo--raw-overlay nil)
(defvar aes-demo--encrypted-overlay nil)
(defvar aes-demo--rounding-overlay nil)

(defun aes-demo-encrypt ()
  (interactive)
  (aes-demo--activate t)
  (unwind-protect 
      (let ((inhibit-read-only t)
            buffer-read-only)
        (save-excursion
          (flet ((aes--read-passwd (&rest dummy) (vconcat "d")))
            (setq aes-demo--rest-of-decoded nil)
            (goto-char (point-min))
            (aes-demo--create-overlays)
            (aes-encrypt "dummy")
            (aes-demo--clearnup-overlays)))
        (set-buffer-multibyte nil)
        (goto-char (point-max)))
    (aes-demo--activate nil)))

(defun aes-demo-decrypt ()
  (interactive)
  (aes-demo--activate t)
  (unwind-protect 
      (let ((inhibit-read-only t)
            buffer-read-only)
        (save-excursion
          (flet ((aes--read-passwd (&rest dummy) (vconcat "d")))
            (goto-char (point-min))
            (aes-demo--create-overlays)
            (aes-decrypt aes-algorithm "dummy")
            (aes-demo--clearnup-overlays)))
        (goto-char (point-max)))
    (aes-demo--activate nil)))

(defun aes-demo--create-overlays ()
  (let ((raw-ov (make-overlay (point-min) (point-max)))
        (enc-ov (make-overlay (point-min) (point-min)))
        (tmp-ov (make-overlay (point-min) (point-min))))
    (overlay-put raw-ov 'face `((foreground-color . "black") (background-color . "pink")))
    (overlay-put enc-ov 'face `((foreground-color . "black") (background-color . "sky blue")))
    (overlay-put tmp-ov 'face `((foreground-color . "black") (background-color . "yellow")))
    (setq aes-demo--raw-overlay raw-ov)
    (setq aes-demo--encrypted-overlay enc-ov)
    (setq aes-demo--rounding-overlay tmp-ov)))

(defun aes-demo--clearnup-overlays ()
  (delete-overlay aes-demo--raw-overlay)
  (delete-overlay aes-demo--encrypted-overlay)
  (delete-overlay aes-demo--rounding-overlay)
  (setq aes-demo--raw-overlay nil)
  (setq aes-demo--encrypted-overlay nil)
  (setq aes-demo--rounding-overlay nil))

(defun aes--demo-parse-buffer-for-encrypt ()
  (let ((start (point)))
    (save-excursion
      (loop with data = aes-demo--rest-of-decoded
            append (let ((enc (encode-coding-char (char-after) buffer-file-coding-system)))
                     (string-to-list enc)) into data
            do (forward-char)
            while (and (< (length data) (* aes--Nb aes--Row)) 
                       (char-after))
            ;; split encoded chars
            finally return (loop for d on data
                                 for i from 0 below (* aes--Nb aes--Row)
                                 append (list (car d)) into parsed
                                 finally return 
                                 (progn
                                   (sit-for 0.1)
                                   (delete-region start (point))
                                   (setq aes-demo--rest-of-decoded d)
                                   (list (aes--unibytes-to-state (vconcat parsed)) (not (eobp)))))))))

(defun aes--demo-parse-buffer-for-decrypt ()
  (let ((start (point))
        (end (+ (point) (* aes--Nb aes--Row))))
    (save-excursion
      (let ((enc (buffer-substring start end)))
        (sit-for 0.1)
        (delete-region start end)
        (list (aes--unibytes-to-state (string-to-list enc)) (not (eobp)))))))

(defun aes-demo--draw-state (state)
  (let ((start (point)))
    (apply 'insert (aes--state-to-bytes state))
    (move-overlay aes-demo--rounding-overlay start (point))
    (sit-for 0.001)
    (delete-region start (point))))

(defconst aes-demo--advice-alist
  '(
    ;; (aes--state-to-bytes    aes-demo--state-to-bytes  around)
    (aes--cbc-encrypt       aes-demo--cbc-encrypt     around)
    (aes--cbc-decrypt       aes-demo--cbc-decrypt     around)
    (aes--ecb-encrypt       aes-demo--ecb-encrypt     around)
    (aes--ecb-decrypt       aes-demo--ecb-decrypt     around)
    (aes--cipher            aes-demo--cipher          around)
    (aes--inv-cipher        aes-demo--inv-cipher      around)
    (aes--add-round-key     aes-demo--add-round-key   around)
    (aes--mix-columns       aes-demo--mix-columns     around)
    (aes--inv-mix-columns   aes-demo--inv-mix-columns around)
    (aes--shift-rows        aes-demo--shift-rows      around)
    (aes--inv-shift-rows    aes-demo--inv-shift-rows  around)
    (aes--sub-bytes         aes-demo--sub-bytes       around)
    (aes--inv-sub-bytes     aes-demo--inv-sub-bytes   around)
    (aes--parse-unibytes    aes-demo--parse-unibytes  around)
    (aes--parse-salt        aes-demo--parse-salt      around)
    (aes--parse-encrypted   aes-demo--parse-encrypted around)
    ))

(defun aes-demo--activate (flag)
  (loop for pair in aes-demo--advice-alist
        do (destructuring-bind (function name class) pair
             (if flag
                 (ad-enable-advice function class name)
               (ad-disable-advice function class name))
             (ad-activate function))))

(defadvice aes--cbc-encrypt
  (around aes-demo--cbc-encrypt (&rest dummy) disable)
  (insert aes--openssl-magic-word (apply 'aes--unibyte-string (append salt nil)))
  (sit-for 0.3)
  (setq ad-return-value ad-do-it))

(defadvice aes--cbc-decrypt
  (around aes-demo--cbc-decrypt (&rest dummy) disable)
  (setq ad-return-value ad-do-it))

(defadvice aes--ecb-encrypt
  (around aes-demo--ecb-encrypt (&rest dummy) disable)
  (insert aes--openssl-magic-word (apply 'aes--unibyte-string (append salt nil)))
  (sit-for 0.3)
  (setq ad-return-value ad-do-it))

(defadvice aes--ecb-decrypt
  (around aes-demo--ecb-decrypt (&rest dummy) disable)
  (setq ad-return-value ad-do-it))

(defadvice aes--state-to-bytes
  (around aes-demo--state-to-bytes (state) disable)
  (setq ad-return-value ad-do-it))

(defadvice aes--parse-unibytes
  (around aes-demo--parse-unibytes (dummy) disable)
  (setq ad-return-value (aes--demo-parse-buffer-for-encrypt)))

(defadvice aes--parse-salt
  (around aes-demo--parse-salt (dummy) disable)
  (setq ad-return-value
        (list
         (buffer-substring (point-min) 
                           (+ (point-min)
                              (length aes--openssl-magic-word) 
                              aes--pkcs5-salt-length))
         "dummy")))

(defadvice aes--parse-encrypted
  (around aes-demo--parse-encrypted (dummy) disable)
  (setq ad-return-value (aes--demo-parse-buffer-for-decrypt)))

(defadvice aes--cipher 
  (around aes-demo--cipher (state key) disable)
  (setq ad-return-value ad-do-it)
  (apply 'insert (aes--state-to-bytes ad-return-value))
  (move-overlay aes-demo--raw-overlay (point) (point-max))
  (move-overlay aes-demo--encrypted-overlay (point-min) (point))
  (save-excursion
    (apply 'insert aes-demo--rest-of-decoded))
  (sit-for 0.3))

(defadvice aes--inv-cipher 
  (around aes-demo--inv-cipher (state key) disable)
  (setq ad-return-value ad-do-it)
  (aes-demo--draw-state ad-return-value))

(defadvice aes--add-round-key 
  (around aes-demo--add-round-key (state round-key) disable)
  (setq ad-return-value ad-do-it)
  (aes-demo--draw-state ad-return-value))

(defadvice aes--mix-columns 
  (around aes-demo--mix-columns (state) disable)
  (setq ad-return-value ad-do-it)
  (aes-demo--draw-state ad-return-value))

(defadvice aes--inv-mix-columns 
  (around aes-demo--inv-mix-columns (state) disable)
  (setq ad-return-value ad-do-it)
  (aes-demo--draw-state ad-return-value))

(defadvice aes--shift-rows 
  (around aes-demo--shift-rows (state) disable)
  (setq ad-return-value ad-do-it)
  (aes-demo--draw-state ad-return-value))

(defadvice aes--inv-shift-rows 
  (around aes-demo--inv-shift-rows (state) disable)
  (setq ad-return-value ad-do-it)
  (aes-demo--draw-state ad-return-value))

(defadvice aes--sub-bytes 
  (around aes-demo--sub-bytes (state) disable)
  (setq ad-return-value ad-do-it)
  (aes-demo--draw-state ad-return-value))

(defadvice aes--inv-sub-bytes 
  (around aes-demo--inv-sub-bytes (state) disable)
  (setq ad-return-value ad-do-it)
  (aes-demo--draw-state ad-return-value))

(provide 'aes-demo)
