;;;; tests cl+ssl's ffi-buffer-clisp.lisp's s/b-replace and b/s-replace.
;;;; a successful run is when (test-ffi-buffer-clisp) raises no errors.

(in-package "CL+SSL")
(export '(TEST-FFI-BUFFER-CLISP))

;; The number of extra bytes allocated in the end of the buffer.
;; The bytes are zeroed, and after each test case we
;; verify if they stay zeroed to detect buffer overflow.
(defparameter *buf-extra-len* 10)

(defun create-test-buffer (length &optional data)
  (let ((result (make-buffer (+ length *buf-extra-len*))))
    (dotimes (i (buffer-length result))
      (setf (buffer-elt result i)
            (if (and data (< i (length data)))
                (aref data i)
                0)))
    (setf (clisp-ffi-buffer-size result) length)
    result))

(defun buffer-equal (expected-vec buf)
  (dotimes (i (length expected-vec) t)
    (unless (equal (aref expected-vec i) (buffer-elt buf i))
      (return nil)))
  (dotimes (i *buf-extra-len* t)
    (let ((pos (+ (buffer-length buf) i)))
      (unless (equal 0 (buffer-elt buf pos))
        (return nil)))))

;; Temporary definitions for the symbols from the new
;; ffi-buffer-clisp code, that are reffered by the test.
;; To make it compilable agains the olc cl+ssl.
(defvar *mem-max* 1024)

(defun release-buffer (buf)
  (ffi:foreign-free (clisp-ffi-buffer-pointer buf)))

(defun with-test-buffer-impl (length data body-fn)
  (let ((buf (create-test-buffer length data)))
    (unwind-protect
         (funcall body-fn buf)
      (release-buffer buf))))

(defmacro with-test-buffer ((buf-var length &optional data) &body body)
  `(with-test-buffer-impl ,length ,data (lambda (,buf-var) ,@body)))

(with-test-buffer (buf 3 #(1 2 3))
  (assert (= (buffer-elt buf 1))))

;; Returns buffer bytes and its extended memory bytes
;; as an array, with "|" placed between data bytes and the
;; extended bytes
(defgeneric buf-view (buf))

(defmethod buf-view ((buf clisp-ffi-buffer))
  (let ((result (make-array (+ (buffer-length buf)
                               *buf-extra-len*
                               1)
                            :fill-pointer 0)))
    (dotimes (i (buffer-length buf))
      (vector-push (buffer-elt buf i) result))
    (vector-push "|" result)
    (dotimes (i *buf-extra-len*)
      (vector-push (buffer-elt buf (+ (buffer-length buf) i))
                    result))
    result))

(with-test-buffer (buf 4 #(1 2 3 4))
  (assert (equalp #(1 2 3 4 "|" 0 0 0 0 0 0 0 0 0 0)
                  (buf-view buf))))

(defmethod buf-view ((expected-vec array))
  (let ((result (make-array (+ (length expected-vec)
                               *buf-extra-len*
                               1)
                            :fill-pointer (length expected-vec))))
    (replace result expected-vec)
    (vector-push "|" result)
    (dotimes (_ *buf-extra-len*)
      (vector-push 0 result))
    result))

(assert (equalp #(1 2 3 "|" 0 0 0 0 0 0 0 0 0 0)
                (buf-view #(1 2 3))))

(defun assert-buf-equal (expected-vec buf)
  (assert (buffer-equal expected-vec buf)
          () "padded buffer is not exqual to~%~S:~%~S"
          (buf-view expected-vec)
          (buf-view buf)))

(defun test-b/s-replace ()
  (mapc #'(lambda (vec expected-buf)
            (mapc #'(lambda (seq)
                      (mapc #'(lambda (*mem-max*)
                                (with-test-buffer (buf 4)
                                  (let ((end (min (buffer-length buf)
                                                  (length seq))))
                                    (b/s-replace buf seq :start1 0 :end1 end
                                                         :start2 0 :end2 end)
                                    (assert-buf-equal expected-buf buf)))
                                (with-test-buffer (buf 4)
                                  (b/s-replace buf seq :start1 0
                                                       :start2 0 :end2 (length seq))
                                  (assert-buf-equal expected-buf buf)))
                            (list *mem-max* 2)))
                  (list vec (map 'list #'identity vec))))
        (list #(0 1 2)   #(0 1 2 3) #(0 1 2 3 4))
        (list #(0 1 2 0) #(0 1 2 3) #(0 1 2 3)))
  (values))

(defun test-s/b-replace ()
  (mapc #'(lambda (vec-len buf-data expected-vec)
            (mapc #'(lambda (*mem-max*)
                      (let ((buf (create-test-buffer (length buf-data)
                                                     buf-data))
                            (vec (make-array vec-len
                                             :element-type '(unsigned-byte 8)
                                             :initial-element 0)))
                        (unwind-protect
                          (let ((end (min (buffer-length buf) (length vec))))
                            (s/b-replace vec buf :start1 0 :end1 end
                                                 :start2 0 :end2 end)
                            (assert (equalp expected-vec vec)))
                          (release-buffer buf))))
                  (list *mem-max* 2)))
        (list 2          4          6)
        (list #(0 1 2 3) #(0 1 2 3) #(0 1 2 3))
        (list #(0 1)     #(0 1 2 3) #(0 1 2 3 0 0)))
  (values))

(defun test-ffi-buffer-clisp ()
  (test-b/s-replace)
  (test-s/b-replace))

(test-ffi-buffer-clisp)
