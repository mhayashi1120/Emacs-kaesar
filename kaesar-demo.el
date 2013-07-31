
(defvar kaesar-demo--rest-of-decoded nil)
(defvar kaesar-demo--raw-overlay nil)
(defvar kaesar-demo--encrypted-overlay nil)
(defvar kaesar-demo--rounding-overlay nil)

(defun kaesar-demo-encrypt ()
  (interactive)
  (cipher/aes-demo--activate t)
  (unwind-protect 
      (let ((inhibit-read-only t)
            buffer-read-only)
        (save-excursion
          (flet ((cipher/aes--read-passwd (&rest dummy) (vconcat "d")))
            (setq kaesar-demo--rest-of-decoded nil)
            (goto-char (point-min))
            (cipher/aes-demo--create-overlays)
            (cipher/aes-encrypt "dummy")
            (cipher/aes-demo--clearnup-overlays)))
        (set-buffer-multibyte nil)
        (goto-char (point-max)))
    (cipher/aes-demo--activate nil)))

(defun kaesar-demo-decrypt ()
  (interactive)
  (cipher/aes-demo--activate t)
  (unwind-protect 
      (let ((inhibit-read-only t)
            buffer-read-only)
        (save-excursion
          (flet ((cipher/aes--read-passwd (&rest dummy) (vconcat "d")))
            (goto-char (point-min))
            (cipher/aes-demo--create-overlays)
            (cipher/aes-decrypt kaesar-algorithm "dummy")
            (cipher/aes-demo--clearnup-overlays)))
        (goto-char (point-max)))
    (cipher/aes-demo--activate nil)))

(defun kaesar-demo--create-overlays ()
  (let ((raw-ov (make-overlay (point-min) (point-max)))
        (enc-ov (make-overlay (point-min) (point-min)))
        (tmp-ov (make-overlay (point-min) (point-min))))
    (overlay-put raw-ov 'face `((foreground-color . "black") (background-color . "pink")))
    (overlay-put enc-ov 'face `((foreground-color . "black") (background-color . "sky blue")))
    (overlay-put tmp-ov 'face `((foreground-color . "black") (background-color . "yellow")))
    (setq kaesar-demo--raw-overlay raw-ov)
    (setq kaesar-demo--encrypted-overlay enc-ov)
    (setq kaesar-demo--rounding-overlay tmp-ov)))

(defun kaesar-demo--clearnup-overlays ()
  (delete-overlay kaesar-demo--raw-overlay)
  (delete-overlay kaesar-demo--encrypted-overlay)
  (delete-overlay kaesar-demo--rounding-overlay)
  (setq kaesar-demo--raw-overlay nil)
  (setq kaesar-demo--encrypted-overlay nil)
  (setq kaesar-demo--rounding-overlay nil))

(defun kaesar--demo-parse-buffer-for-encrypt ()
  (let ((start (point)))
    (save-excursion
      (loop with data = kaesar-demo--rest-of-decoded
            append (let ((enc (encode-coding-char (char-after) buffer-file-coding-system)))
                     (string-to-list enc)) into data
            do (forward-char)
            while (and (< (length data) (* kaesar--Nb kaesar--Row)) 
                       (char-after))
            ;; split encoded chars
            finally return (loop for d on data
                                 for i from 0 below (* kaesar--Nb kaesar--Row)
                                 append (list (car d)) into parsed
                                 finally return 
                                 (progn
                                   (sit-for 0.1)
                                   (delete-region start (point))
                                   (setq kaesar-demo--rest-of-decoded d)
                                   (list (cipher/aes--unibytes-to-state (vconcat parsed)) (not (eobp)))))))))

(defun kaesar--demo-parse-buffer-for-decrypt ()
  (let ((start (point))
        (end (+ (point) (* kaesar--Nb kaesar--Row))))
    (save-excursion
      (let ((enc (buffer-substring start end)))
        (sit-for 0.1)
        (delete-region start end)
        (list (cipher/aes--unibytes-to-state (string-to-list enc)) (not (eobp)))))))

(defun kaesar-demo--draw-state (state)
  (let ((start (point)))
    (apply 'insert (cipher/aes--state-to-bytes state))
    (move-overlay kaesar-demo--rounding-overlay start (point))
    (sit-for 0.001)
    (delete-region start (point))))

(defconst kaesar-demo--advice-alist
  '(
    ;; (cipher/aes--state-to-bytes    kaesar-demo--state-to-bytes  around)
    (cipher/aes--cbc-encrypt       kaesar-demo--cbc-encrypt     around)
    (cipher/aes--cbc-decrypt       kaesar-demo--cbc-decrypt     around)
    (cipher/aes--ecb-encrypt       kaesar-demo--ecb-encrypt     around)
    (cipher/aes--ecb-decrypt       kaesar-demo--ecb-decrypt     around)
    (cipher/aes--cipher            kaesar-demo--cipher          around)
    (cipher/aes--inv-cipher        kaesar-demo--inv-cipher      around)
    (cipher/aes--add-round-key     kaesar-demo--add-round-key   around)
    (cipher/aes--mix-columns       kaesar-demo--mix-columns     around)
    (cipher/aes--inv-mix-columns   kaesar-demo--inv-mix-columns around)
    (cipher/aes--shift-rows        kaesar-demo--shift-rows      around)
    (cipher/aes--inv-shift-rows    kaesar-demo--inv-shift-rows  around)
    (cipher/aes--sub-bytes         kaesar-demo--sub-bytes       around)
    (cipher/aes--inv-sub-bytes     kaesar-demo--inv-sub-bytes   around)
    (cipher/aes--parse-unibytes    kaesar-demo--parse-unibytes  around)
    (cipher/aes--parse-salt        kaesar-demo--parse-salt      around)
    (cipher/aes--parse-encrypted   kaesar-demo--parse-encrypted around)
    ))

(defun kaesar-demo--activate (flag)
  (loop for pair in kaesar-demo--advice-alist
        do (destructuring-bind (function name class) pair
             (if flag
                 (ad-enable-advice function class name)
               (ad-disable-advice function class name))
             (ad-activate function))))

(defadvice cipher-aes--cbc-encrypt
  (around kaesar-demo--cbc-encrypt (&rest dummy) disable)
  (insert cipher-aes--openssl-magic-word (apply 'cipher-aes--unibyte-string (append salt nil)))
  (sit-for 0.3)
  (setq ad-return-value ad-do-it))

(defadvice cipher-aes--cbc-decrypt
  (around kaesar-demo--cbc-decrypt (&rest dummy) disable)
  (setq ad-return-value ad-do-it))

(defadvice cipher-aes--ecb-encrypt
  (around kaesar-demo--ecb-encrypt (&rest dummy) disable)
  (insert cipher-aes--openssl-magic-word (apply 'cipher-aes--unibyte-string (append salt nil)))
  (sit-for 0.3)
  (setq ad-return-value ad-do-it))

(defadvice cipher-aes--ecb-decrypt
  (around kaesar-demo--ecb-decrypt (&rest dummy) disable)
  (setq ad-return-value ad-do-it))

(defadvice cipher-aes--state-to-bytes
  (around kaesar-demo--state-to-bytes (state) disable)
  (setq ad-return-value ad-do-it))

(defadvice cipher-aes--parse-unibytes
  (around kaesar-demo--parse-unibytes (dummy) disable)
  (setq ad-return-value (cipher/aes--demo-parse-buffer-for-encrypt)))

(defadvice cipher-aes--parse-salt
  (around kaesar-demo--parse-salt (dummy) disable)
  (setq ad-return-value
        (list
         (buffer-substring (point-min) 
                           (+ (point-min)
                              (length cipher-aes--openssl-magic-word) 
                              cipher-aes--pkcs5-salt-length))
         "dummy")))

(defadvice cipher-aes--parse-encrypted
  (around kaesar-demo--parse-encrypted (dummy) disable)
  (setq ad-return-value (cipher/aes--demo-parse-buffer-for-decrypt)))

(defadvice cipher-aes--cipher 
  (around kaesar-demo--cipher (state key) disable)
  (setq ad-return-value ad-do-it)
  (apply 'insert (cipher/aes--state-to-bytes ad-return-value))
  (move-overlay kaesar-demo--raw-overlay (point) (point-max))
  (move-overlay kaesar-demo--encrypted-overlay (point-min) (point))
  (save-excursion
    (apply 'insert kaesar-demo--rest-of-decoded))
  (sit-for 0.3))

(defadvice cipher-aes--inv-cipher 
  (around kaesar-demo--inv-cipher (state key) disable)
  (setq ad-return-value ad-do-it)
  (cipher/aes-demo--draw-state ad-return-value))

(defadvice cipher-aes--add-round-key 
  (around kaesar-demo--add-round-key (state round-key) disable)
  (setq ad-return-value ad-do-it)
  (cipher/aes-demo--draw-state ad-return-value))

(defadvice cipher-aes--mix-columns 
  (around kaesar-demo--mix-columns (state) disable)
  (setq ad-return-value ad-do-it)
  (cipher/aes-demo--draw-state ad-return-value))

(defadvice cipher-aes--inv-mix-columns 
  (around kaesar-demo--inv-mix-columns (state) disable)
  (setq ad-return-value ad-do-it)
  (cipher/aes-demo--draw-state ad-return-value))

(defadvice cipher-aes--shift-rows 
  (around kaesar-demo--shift-rows (state) disable)
  (setq ad-return-value ad-do-it)
  (cipher/aes-demo--draw-state ad-return-value))

(defadvice cipher-aes--inv-shift-rows 
  (around kaesar-demo--inv-shift-rows (state) disable)
  (setq ad-return-value ad-do-it)
  (cipher/aes-demo--draw-state ad-return-value))

(defadvice cipher-aes--sub-bytes 
  (around kaesar-demo--sub-bytes (state) disable)
  (setq ad-return-value ad-do-it)
  (cipher/aes-demo--draw-state ad-return-value))

(defadvice cipher-aes--inv-sub-bytes 
  (around kaesar-demo--inv-sub-bytes (state) disable)
  (setq ad-return-value ad-do-it)
  (cipher/aes-demo--draw-state ad-return-value))

(provide 'kaesar-demo)
