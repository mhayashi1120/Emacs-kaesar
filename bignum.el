;;; bignum.el --- Handling huge number

;; Author: Masahiro Hayashi <mhayashi1120@gmail.com>
;; Keywords: Number
;; URL: http://github.com/mhayashi1120/Emacs-cipher/raw/master/cipher/bignum.el
;; Emacs: GNU Emacs 22 or later
;; Version 0.1.0

(defconst bignum-version "0.1.0")

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
;;     (require 'bignum)

;;; Usage:

;; Bignum support huge Natural number and `0' manupulations.

;;; TODO:

;;; Code:

(eval-when-compile
  (require 'cl))

(defvar bignum--number-bit 31)

(defconst bignum--base-bit (/ bignum--number-bit 2)
  "Half bit of number. That make hold result of multiplying two values to Emacs number.")

(defconst bignum--base (lsh 1 bignum--base-bit))
(defconst bignum--mask (1- bignum--base))
(defconst bignum--mask-low (1- bignum--base))
(defconst bignum--mask-high (lsh bignum--mask-low bignum--base-bit))

(defun bignum (number)
  (or
   (loop while (> number 0)
         collect (let ((n (mod number bignum--base)))
                   (setq number (/ number bignum--base))
                   n))
   (copy-sequence '(0))))

(defconst bignum--zero (bignum 0))
(defconst bignum--one (bignum 1))

(defun bignum-normalize (bignum)
  (or
   (loop for n on (reverse bignum)
         unless (zerop (car n))
         return (nreverse n))
   (bignum-zero)))

(defun bignum-zero ()
  (copy-sequence bignum--zero))

(defun bignum-one ()
  (copy-sequence bignum--one))

;;
;; Basic calculations
;;

(defun bignum-add (bignum1 bignum2)
  "Add BIGNUM1 and BIGNUM2."
  (loop with raise = 0
        while (or bignum1 bignum2 (> raise 0))
        collect (let ((tmp (apply '+ (remove nil (list (car bignum1) (car bignum2) raise)))))
                  (setq raise (/ tmp bignum--base))
                  (mod tmp bignum--base))
        do (setq bignum1 (cdr bignum1) bignum2 (cdr bignum2))))

(defun bignum-diff (bignum1 bignum2)
  "Subtracted absolute value"
  (let (b1 b2)
    (if (bignum>= bignum1 bignum2)
        (setq b1 bignum1 b2 bignum2)
      (setq b1 bignum2 b2 bignum1))
    ;; copy
    (setq b1 (copy-sequence b1))
    ;; fill by 0
    (setq b2 (append b2 (make-list (- (length b1) (length b2)) 0)))
    (loop with res = nil
          for n1 in (nreverse b1)
          for n2 in (nreverse b2)
          do (let ((v
                    (cond
                     ((= n1 n2) 0)
                     ((> n1 n2)
                      (- n1 n2))
                     (t
                      (if (eq (car res) 1)
                          (setq res (cdr res))
                        (setcar res (1- (car res))))
                      (- (+ n1 bignum--base) n2)))))
               (unless (and (zerop v) (null res))
                 (setq res (cons v res))))
          finally return (or res (bignum-zero)))))

(defun bignum-mul (bignum1 bignum2)
  "Multiply BIGNUM1 by BIGNUM2."
  (loop with acc = (bignum-zero)
        for n1 in bignum1
        for i from 0
        do (let ((tmp (loop with raise = 0
                            for n2 in bignum2
                            collect (let ((h&l (bignum--high&low (+ raise (* n1 n2)))))
                                      (setq raise (car h&l))
                                      (cdr h&l))
                            into res
                            finally return (if (> raise 0) (nconc res (list raise)) res))))
             (setq acc (bignum-add (bignum--raise tmp i) acc)))
        finally return (bignum-normalize acc)))

(defun bignum-modulo-product (modulo bignum1 bignum2)
  (loop with pow = (bignum-one)
        for b2 = bignum2 then (bignum-rshift b2 1)
        for base = bignum1 then (bignum-mod (bignum-mul base base) modulo)
        until (bignum-zerop b2)
        do (progn
             (unless (bignum-zerop (bignum-logand bignum--one b2))
               (setq pow (bignum-mod (bignum-mul pow base) modulo))))
        finally return pow))

(defun bignum-power (bignum power)
  (loop with b = (bignum-one)
        with p = power
        until (bignum-zerop p)
        do (setq b (bignum-mul bignum b)
                 p (bignum-1- p))
        finally return b))

(defun bignum-div&rem (dividen divisor)
  (cond
   ((bignum= divisor bignum--zero)
    (signal 'arith-error nil))
   ((bignum= divisor bignum--one)
    (cons dividen (bignum-zero)))
   ((bignum< dividen divisor)
    (cons (bignum-zero) dividen))
   ((bignum= dividen divisor)
    (cons (bignum-one) (bignum-zero)))
   (t
    (bignum--div&rem-0 dividen divisor))))

(defun bignum-div (dividend divisor)
  (car (bignum-div&rem dividend divisor)))

(defun bignum-mod (x y)
  (cdr (bignum-div&rem x y)))

;;
;; Serialize
;;

(defun bignum-serialize (bignum byte &optional little-endian allow-overflow)
  (let* ((bytes (loop for (div . rem) = (cons bignum nil)
                      then (bignum-div&rem div (bignum ?\x100))
                      until (bignum-zerop div)
                      if rem
                      collect rem into res
                      finally return (mapcar 
                                      (lambda (x) (bignum-to-number x))
                                      (cons rem (nreverse res)))))
         (len (length bytes))
         (block (cond
                 ((> len byte) 
                  (unless allow-overflow
                    (signal 'arith-error (list "Overflow" bignum)))
                  (nthcdr (- len byte) bytes))
                 (t
                  (append (make-list (- byte len) 0) bytes)))))
    (vconcat
     (if little-endian
         (nreverse block)
       block))))

(defun bignum-read-bytes (bytes count &optional little-endian)
  (let* ((data (loop for b in bytes
                     repeat count
                     collect b into res
                     finally return 
                     (progn 
                       (when (< (length res) count)
                         (error "Unable read %s byte(s) from %s" count bytes))
                       res)))
         (value (bignum-from-bytes data))
         (rest (nthcdr count bytes)))
    (list value rest)))

(defun bignum-read-byte (bytes &optional little-endian)
  (bignum-read-bytes bytes 1 little-endian))

(defun bignum-read-int16 (bytes &optional little-endian)
  (bignum-read-bytes bytes 2 little-endian))

(defun bignum-read-int32 (bytes &optional little-endian)
  (bignum-read-bytes bytes 4 little-endian))

(defun bignum-read-int64 (bytes &optional little-endian)
  (bignum-read-bytes bytes 8 little-endian))

;;
;; Bit operation 
;;

(defun bignum-logand (bignum1 bignum2)
  (loop for b1 in bignum1
        for b2 in bignum2
        collect (logand b1 b2)))

(defun bignum-logior (bignum1 bignum2)
  (loop for b1 = bignum1 then (cdr b1)
        for b2 = bignum2 then (cdr b2)
        while (or b1 b2)
        collect (logior (or (car b1) 0) (or (car b2) 0))))

(defun bignum-logxor (bignum1 bignum2)
  (loop for b1 = bignum1 then (cdr b1)
        for b2 = bignum2 then (cdr b2)
        while (or b1 b2)
        collect (logxor (or (car b1) 0) (or (car b2) 0))))

(defun bignum-rshift (bignum count)
  (if (minusp count)
      (bignum-lshift bignum (- count))
    (let ((div (/ count bignum--base-bit))
          (rem (% count bignum--base-bit))
          (num (copy-sequence bignum)))
      (when (> div 0)
        ;; drop overflowed cell
        (setq num (bignum--drop num div)))
      (when (> rem 0)
        (loop with borrow = 0
              with res = nil
              for n in (nreverse num)
              do (let* ((h&l (bignum--high&low (lsh (lsh n bignum--base-bit) (- rem))))
                        (v (logior borrow (car h&l))))
                   (when (or (not (zerop v))
                             res)
                     (setq res (cons v res)))
                   (setq borrow (cdr h&l)))
              finally (setq num (or res (bignum-zero)))))
      num)))

(defun bignum-lshift (bignum count)
  (if (minusp count)
      (bignum-rshift bignum (- count))
    (let ((div (/ count bignum--base-bit))
          (rem (% count bignum--base-bit))
          (num (copy-sequence bignum)))
      (when (> div 0)
        (setq num (nconc (make-list div 0) num)))
      (when (> rem 0)
        (loop with raise = 0
              for n on num
              do (let ((h&l (bignum--high&low (lsh (car n) rem))))
                   (setcar n (logior (cdr h&l) raise))
                   (setq raise (car h&l)))
              finally (when (> raise 0) 
                        (setq num (nconc num (list raise))))))
      num)))

(defun bignum-bits (bignum)
  (+ (* (1- (length bignum)) bignum--base-bit)
     (loop with v = (car (last bignum))
           for i from 0
           while (and (> v 0) (logand v 1))
           do (setq v (lsh v -1))
           finally return i)))

;;
;; Basic utility
;;

(defun bignum-1- (bignum)
  (bignum-diff bignum bignum--one))

(defun bignum-1+ (bignum)
  (bignum-add bignum bignum--one))

;;
;; Basic predicate
;;

(defun bignum-zerop (bignum)
  (equal bignum bignum--zero))

(defun bignum-p (obj)
  (and (listp obj)
       (loop for a in obj
             if (or (not (numberp a))
                    (< a 0)
                    (<= bignum--base a))
             return nil)))

(defun bignum-oddp (bignum)
  (eq (logand (car bignum) 1) 1))

(defun bignum-evenp (bignum)
  (eq (logand (car bignum) 1) 0))

(defun bignum= (bignum1 bignum2)
  (equal bignum1 bignum2))

(defun bignum/= (bignum1 bignum2)
  (not (bignum= bignum1 bignum2)))

(defun bignum< (bignum1 bignum2)
  (let ((l1 (length bignum1))
        (l2 (length bignum2)))
    (cond
     ((= l1 l2)
      (loop for n1 in (reverse bignum1)
            for n2 in (reverse bignum2)
            if (< n1 n2)
            return t
            if (> n1 n2)
            return nil))
     (t
      (< l1 l2)))))

(defun bignum<= (bignum1 bignum2)
  (or (bignum= bignum1 bignum2)
      (bignum< bignum1 bignum2)))

(defun bignum> (bignum1 bignum2)
  (not (bignum<= bignum1 bignum2)))

(defun bignum>= (bignum1 bignum2)
  (or (bignum= bignum1 bignum2)
      (bignum> bignum1 bignum2)))

;;;
;;; Formatter
;;;

(defconst bignum--string-chars
  [
   ?0 ?1 ?2 ?3 ?4 ?5 ?6 ?7 ?8 ?9
      ?a ?b ?c ?d ?e ?f ?g ?h ?i ?j ?k ?l ?m
      ?n ?o ?p ?q ?r ?s ?t ?u ?v ?w ?x ?y ?z
   ])

(defconst bignum--chars-table
  (loop with vec = (make-vector (1+ (apply 'max (append bignum--string-chars nil))) nil)
        for v across bignum--string-chars
        for i from 0
        do (aset vec v i)
        finally return vec))

(defun bignum-to-string (bignum &optional base)
  (when (and base
             (or (< base 2)
                 (< 36 base)))
    (signal 'args-out-of-range (list base)))
  (unless base 
    (setq base 16))
  (or
   (let* ((l (log base 2))
          (bit (truncate l)))
     ;; bit operation
     (and (= bit l)
          (loop with full = (1- (lsh 1 bit))
                for i from 0
                until (bignum-zerop bignum)
                collect (aref bignum--string-chars (logand full (car bignum)))
                into res
                do (setq bignum (bignum-rshift bignum bit))
                finally return (concat 
                                (or (nreverse res) 
                                    (list (aref bignum--string-chars 0)))))))
   (let* ((base (bignum base))
          (chars 
           (loop with div = (copy-sequence bignum)
                 until (bignum-zerop div)
                 collect (let ((d&r (bignum-div&rem div base)))
                           (setq div (car d&r))
                           (aref bignum--string-chars (bignum-to-number (cdr d&r)))))))
     (concat (nreverse chars)))))

;;TODO name
(defun bignum-valid-number-p (bignum)
  (or
   (and (eq (logand bignum--number-bit 1) 1)
        (or (<= (length bignum) 3)
            (and (= (length bignum) 3) (<= (nth 2 bignum) 1))))
   (and (eq (logand bignum--number-bit 1) 0)
        (<= (length bignum) 2))))

(defun bignum-to-number (bignum)
  (unless (bignum-valid-number-p bignum)
    (signal 'arith-error (list (format "Overflow %s" bignum))))
  (loop with acc = 0
        for n in bignum
        for i from 0
        sum (logior acc (lsh n (* i bignum--base-bit)))))

(defun bignum-from-string (string &optional base)
  (unless base
    (setq base 16))
  (loop with res = nil
        with basis = (bignum base)
        with tlen = (length bignum--chars-table)
        for b = (bignum-one) then (bignum-mul b basis)
        for i downfrom (1- (length string)) downto 0
        do (let ((c (aref string i)))
             (when (>= c tlen)
               (signal 'parse-error (list (format "Invalid char %c at %d" c i))))
             (let ((n (aref bignum--chars-table (downcase c))))
               (when (or (null n) (>= n base))
                 (signal 'parse-error (list (format "Invalid char %c at %d" c i))))
               (setq res (bignum-add (bignum-mul (bignum n) b) res))))
        finally return res))

(defun bignum-from-bytes (bytes &optional little-endian)
  (let ((hex (mapconcat
              (lambda (x) (format "%02x" x))
               (if little-endian (nreverse bytes) bytes)
               "")))
    (bignum-from-string hex 16)))

(defalias 'bignum-from-number 'bignum)

;;;
;;; Some inner functions
;;;

;;
;; Division and Remainder inner functions
;;
(defun bignum--div&rem-0 (dividend divisor)
  (loop with rem = dividend
        with div = nil
        do (let* ((top&rest (bignum--div-split rem divisor))
                  (d&r (bignum--div&rem-1 (car top&rest) divisor))
                  (digit (length (cdr top&rest))))
             (unless div
               (setq div (make-list (1+ digit) 0)))
             (setcar (nthcdr digit div) (car d&r))
             (setq rem (append (cdr top&rest) (cdr d&r))))
        if (bignum< rem divisor)
        return (cons div rem)))

;;TODO refactor
;; returns '(temporary-dividend . rest-of-dividend)
;; temporary-dividend must greather than DIVISOR
(defun bignum--div-split (dividend divisor)
  (let* ((d1len (length dividend))
         (d2len (length divisor))
         (len (- d1len d2len))        ; (minusp len) means error
         ;; first, same length of DIVISOR
         (tmp (nthcdr len dividend)))
    (when (and tmp (bignum< tmp divisor))
      ;; borrow one more cell if tmp is less than DIVISOR
      (setq tmp (nthcdr (1- len) dividend)))
    (cons tmp (loop repeat (- d1len (length tmp))
                    for d in dividend
                    collect d))))

;; dividend >= divisor
;; calculate quotient (1 digit) and remainder.
(defun bignum--div&rem-1 (dividend divisor)
  (let ((base-div (bignum--msc divisor))
        (d1msc (bignum--msc dividend))
        (d1len (length dividend))
        (d2len (length divisor))
        base-rem rest-rem)
    ;; initialize quotient
    (cond
     ((> d1len d2len)
      (let ((d1msc-1 (bignum--msc dividend 1)))
        (setq base-rem (bignum--number2 d1msc d1msc-1))
        (setq rest-rem (bignum--truncate dividend 1))))
     ;; ((> d1len 1)
     ;;  (let ((d1msc-1 (bignum--msc dividend 1)))
     ;;    (setq base-rem (bignum--number2 d1msc d1msc-1))
     ;;    (setq rest-rem (bignum--truncate dividend 1))
     ;;    (setq base-div (bignum--number2 base-div
     ;;                                    (bignum--msc divisor 1)))))
     (t
      (setq base-rem d1msc)
      (setq rest-rem (bignum--truncate dividend))))
    (let* ((q (/ base-rem base-div))
           (r-1 (% base-rem base-div))
           (rem (bignum-normalize (append rest-rem (list r-1))))
           (rest-div (bignum--truncate divisor)))
      (loop until (loop for i downfrom (1- (length rest-div))
                        for d2 in (reverse rest-div)
                        unless (let* ((m (* q d2))
                                      (r (bignum--div-borrow rem i m)))
                                 (when r
                                   (setq rem r)))
                        return nil
                        finally return t)
            do (progn
                 (setq q (1- q))
                 (when (minusp q)
                   (error "Assert remaining unsubtracted value %s %s" dividend divisor))
                 (let* ((r (+ r-1 base-div))
                        (h&l (bignum--high&low r)))
                   (setq rem (append rest-rem
                                     (if (plusp (car h&l))
                                         (list (cdr h&l) (car h&l))
                                       (list (cdr h&l)))))
                   (setq r-1 r))))
      (cons q rem))))

(defun bignum--div-borrow (bignum digit value2)
  (let ((len (length bignum)))
    (when (< digit len)
      (let* ((bignum (copy-sequence bignum))
             (n1-0 (- (nth digit bignum) value2))
             n2-0)
        (if (>= n1-0 0)
            (progn
              ;; calculation is completed
              (setcar (nthcdr digit bignum) n1-0)
              bignum)
          (when (and (< digit (1- len)) (minusp n1-0))
            ;; minusp n1-0 means `digit' pay all value that is 0 low.
            (setq n2-0 (+ (bignum--number2 (nth (1+ digit) bignum) 0) n1-0))
            (if (>= n2-0 0)
                (let ((h&l (bignum--high&low n2-0))
                      (rest (nthcdr digit bignum)))
                  (setcar rest (cdr h&l))       ; low cell
                  (setcar (cdr rest) (car h&l)) ; high cell
                  (bignum-normalize bignum))
              (when (and (< digit (+ len 2)) (minusp n2-0))
                ;; minusp n1-0 means `digit' low and high cell pay all value.
                (let ((borrow-digit (loop for i from (+ digit 2) below len
                                          if (plusp (nth i bignum))
                                          return i)))
                  (when borrow-digit
                    (setcar (nthcdr borrow-digit bignum) (1- (nth borrow-digit bignum)))
                    (loop for i downfrom (1- borrow-digit) downto (+ digit 2)
                          ;; fill zero cell by max value
                          do (setcar (nthcdr i bignum) bignum--mask))
                    ;; subtract from borrowed value
                    (setq n2-0 (+ (bignum--number2 bignum--mask (1+ bignum--mask)) n2-0))
                    (when (minusp n2-0)
                      (error "Assert div %d" n2-0))
                    (let ((h&l (bignum--high&low n2-0)))
                      (setcar (nthcdr (1+ digit) bignum) (car h&l))
                      (setcar (nthcdr digit bignum) (cdr h&l)))
                    (bignum-normalize bignum)))))))))))

;;
;; Cell level operation
;;

;; MSC == Most Significant Cell 
(defun bignum--msc (bignum &optional n)
  (car (last bignum (and n (1+ n)))))

;; truncate significant cell(s)
(defun bignum--truncate (bignum &optional n)
  (loop for i from 0 below (1- (- (length bignum) (or n 0)))
        for b in bignum
        collect b))

(defun bignum--raise (bignum count)
  (nconc (make-list count 0) bignum))

(defun bignum--drop (bignum count)
  (copy-sequence (nthcdr count bignum)))

(defun bignum--high&low (number)
  (cons (lsh (logand number bignum--mask-high) (- bignum--base-bit))
        (logand number bignum--mask-low)))

(defun bignum--number2 (high low)
  (+ (* high bignum--base) low))

;;;
;;; High level operation
;;;

;; euclid division
(defun bignum-gcd (m n)
  (loop with res = m
        with tmp = nil
        until (bignum-zerop n)
        do (setq res n)
        until (bignum-zerop (setq tmp (bignum-mod m n)))
        do (progn (setq m n) (setq n tmp))
        finally return res))

(defun bignum-lcm (bignum1 bignum2)
  (let* ((gcd (bignum-gcd bignum1 bignum2))
         (div (bignum-div bignum1 gcd)))
    (bignum-mul div bignum2)))

;;TODO remove external command
;; bn_prime.c
;; BN_is_prime_fasttest_ex

(defun bignum-random (bit)
  (bignum-normalize
   (loop with last = (/ bit bignum--base-bit)
         for i from 0 to last
         collect (random (if (/= i last) 
                             bignum--base
                           (lsh 1 (mod bit bignum--base-bit)))))))

(defun bignum-random-prime (bit)
  (loop with prime = nil
        until prime
        do (let ((r (bignum-random bit)))
             (setcar r (1+ (* (/ (car r) 2) 2)))
             (when (bignum--prime-p r)
               (setq prime r)))
        finally return prime))

;;TODO
(defun bignum--prime-p (bignum)
  (with-temp-buffer
    (call-process "openssl" 
                  nil (current-buffer) nil "prime" "-hex"
                  (bignum-to-string bignum 16))
    (goto-char (point-min))
    (looking-at "[0-9a-zA-Z]+ is prime")))

(provide 'bignum)

;;; bignum.el ends here
