
;;TODO stable test about div&rem (not a random test)

(require 'ert)
(require 'bignum)

(defvar bignum-test--random-suite-threshold 256)

(defun bignum-test--mul (n1 n2)
  (unless (bignum-zerop n2)
    (let ((d&r (bignum-div&rem n1 n2)))
      ;; check n1 / n2 = a ... r
      ;;       n2 * a + r = n1
      (should (equal (bignum-add (bignum-mul n2 (car d&r)) (cdr d&r)) n1)))))

(defun bignum-test--div&rem (dividend divisor)
  (bignum-test--random (list dividend divisor)
    (let ((d&r (bignum-div&rem (bignum dividend) (bignum divisor))))
      (should (equal (/ dividend divisor) (bignum-to-number (car d&r))))
      (should (equal (% dividend divisor) (bignum-to-number (cdr d&r)))))))

(defmacro bignum-test--random (random-values &rest form)
  (declare (indent 1))
  `(condition-case err
       (progn ,@form)
     (error
      (signal (car err) (append (cdr err) (list ,random-values))))))

(ert-deftest bignum-test-basic ()
  "Bignum stable test suite"
  :tags '(bignum)
  (should (equal 1 (bignum-to-number '(1))))
  (should (equal (+ 1 300000) (bignum-to-number (bignum-add (bignum 1) (bignum 300000)))))
  (should (equal (* 1 30000) (bignum-to-number (bignum-mul (bignum 1) (bignum 30000)))))
  (should (equal bignum--zero (bignum-mul '(0) '(255))))
  (should (equal bignum--zero (bignum-mul '(0) '(0))))
  (should (equal (bignum 1) (bignum 1)))
  (should (equal (bignum 65000) (bignum 65000)))
  (should-not (equal (bignum 1) (bignum 0)))

  (should (equal '(2 0 0) (bignum--div-borrow '(2 0 3) 2 3)))
  (should (equal '(2 0 1) (bignum--div-borrow '(2 0 3) 2 2)))
  (should (equal `(,bignum--mask ,bignum--mask ,bignum--mask ,bignum--mask ,bignum--mask 1)
                 (bignum--div-borrow '(3 0 0 0 0 2) 0 4)))
  (should-not (bignum--div-borrow '(2 0 3) 2 4))
  (should (equal `(,bignum--mask ,bignum--mask 2) (bignum--div-borrow '(2 0 3) 0 3)))
  (should-error (bignum-from-string "g") :type 'parse-error)
  (should (equal '(10) (bignum-from-string "a")))
  (should (bignum-zerop (bignum-from-string "0"))))


(ert-deftest bignum-test-bitshift ()
  "Random check bit level shift"
  :tags '(bignum)
  (loop repeat bignum-test--random-suite-threshold
          do (let ((x (random (lsh bignum--base 2)))
                   (y (random 7)))
               (bignum-test--random (list x y)
                 (should (equal (bignum-rshift (bignum x) y) (bignum (lsh x (- y)))))
                 (should (equal (bignum-lshift (bignum x) y) (bignum (lsh x y))))))))

(ert-deftest bignum-test-expt ()
  "Random check expt"
  :tags '(bignum)
  (loop repeat bignum-test--random-suite-threshold
        do (let ((x (random bignum--base))
                 (y (random 2)))
             (bignum-test--random (list x y)
               (should (equal (bignum-power (bignum x) (bignum y)) (bignum (expt x y))))))))

(ert-deftest bignum-test-bits ()
  "Random bit and random"
  :tags '(bignum)
  (loop repeat bignum-test--random-suite-threshold
        do (let ((r (bignum-random 100)))
             (should (<= (bignum-bits r) 100)))))

(ert-deftest bignum-test-to-string ()
  "Random serialize to string"
  :tags '(bignum)
  (loop repeat bignum-test--random-suite-threshold
        do (let ((v (abs (random))))
             (should (equal (format "%x" v) (bignum-to-string (bignum v)))))))

(ert-deftest bignum-test-odd/even ()
  "Random odd/even"
  :tags '(bignum)
  (loop repeat bignum-test--random-suite-threshold
        do (let ((n (abs (random))))
             (bignum-test--random (list n)
               (should (equal (bignum-oddp (bignum n)) (oddp n)))
               (should (equal (bignum-evenp (bignum n)) (evenp n)))))))

(ert-deftest bignum-test-div&rem ()
  "Random check division and remainder"
  (loop repeat bignum-test--random-suite-threshold
        do (let* ((max (lsh (logior bignum--mask-low bignum--mask-high) 1))
                  (d1 (random (1+ max)))
                  (d2 (1+ (random max))))
             (bignum-test--div&rem d1 d2))))


(ert-deftest bignum-test-misc ()
  "Random any test"
  :tags '(bignum)

  (loop repeat bignum-test--random-suite-threshold
        do 
        ;; range of multiplying max
        (let ((n1 (random (lsh 1 14)))
              (n2 (random (lsh 1 14))))
          (bignum-test--random (list n1 n2)
            (should (equal (bignum-to-number (bignum-add (bignum n1) (bignum n2))) (+ n1 n2)))
            (should (equal (bignum-to-number (bignum-mul (bignum n1) (bignum n2))) (* n1 n2)))
            (should (equal (bignum-to-number (bignum-diff (bignum n1) (bignum n2))) (abs (- n1 n2))))
            (should (equal (bignum-to-number (bignum-logior (bignum n1) (bignum n2))) (logior n1 n2)))
            (should (equal (bignum-to-number (bignum-logxor (bignum n1) (bignum n2))) (logxor n1 n2)))
            (should (equal (bignum-to-number (bignum-logand (bignum n1) (bignum n2))) (logand n1 n2)))
            (should (equal (bignum< (bignum n1) (bignum n2)) (< n1 n2)))
            (should (equal (bignum> (bignum n1) (bignum n2)) (> n1 n2)))
            (should (equal (bignum-to-number (bignum-gcd (bignum n1) (bignum n2))) (gcd n1 n2)))
            (should (equal (bignum-to-number (bignum-lcm (bignum n1) (bignum n2))) (lcm n1 n2)))
            (should (equal (format "%x" n1) (bignum-to-string (bignum n1))))
            ))))

(ert-deftest bignum-test-huge-multiplying ()
  "Random check division & remainder <-> multiply"
  :tags '(bignum)
  ;; div&rem <-> multiplying
  (loop repeat bignum-test--random-suite-threshold
        do (let ((r1 (bignum-random (random 100)))
                 (r2 (bignum-random (random 100))))
             (bignum-test--random (list r1 r2)
               (bignum-test--mul r1 r2)))))

;;TODO test bignum-serialize

(provide 'bignum-test)
