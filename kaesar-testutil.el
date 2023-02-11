
(defmacro kaesar-test-should (expected-form test-form)
  (declare (indent 1))
  `(should (equal ,expected-form ,test-form)))

(defun kaesar-test---unibytes-to-hex (unibytes)
  (apply 'concat
         (cl-loop for b across unibytes
                  collect (format "%02X" b))))

(defun kaesar-test--hex-to-unibyte (hex)
  (apply 'unibyte-string
         (append (kaesar-test--hex-to-vector hex) nil)))

(defun kaesar-test--hex-to-vector (hex)
  (cl-loop with len = (length hex)
           with vec = (make-vector (/ len 2) nil)
           for i from 0 below len by 2
           for j from 0
           collect (let* ((s (substring hex i (+ i 2)))
                          (n (string-to-number s 16)))
                     (aset vec j n))
           finally return vec))


(provide 'kaesar-testutil)
