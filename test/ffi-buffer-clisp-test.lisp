;;;; tests cl+ssl's ffi-buffer-clisp.lisp's s/b-replace and b/s-replace.
;;;; a successful run is when (test-ffi-buffer-clisp) raises no errors.

(in-package "CL+SSL")
(export '(TEST-FFI-BUFFER-CLISP))

(defun create-test-buffer (length &optional data)
  (let ((result (make-buffer length)))
    (dotimes (i (buffer-length result) result)
      (setf (buffer-elt result i) (if data (aref data i) 0)))))

(defun buffer-equal (expected-vec buf)
  (dotimes (i (length expected-vec) t)
    (unless (equal (aref expected-vec i) (buffer-elt buf i))
      (return nil))))

;; Temporarily definitions for the symbols from the new
;; ffi-buffer-clisp code, that are reffered by the test.
;; To make it compilable agains the olc cl+ssl.
(defvar *mem-max* 1024)
(defun release-buffer (buf)
  (ffi:foreign-free (clisp-ffi-buffer-pointer buf)))

(defun test-b/s-replace ()
  (mapc #'(lambda (vec expected-buf)
            (mapc #'(lambda (seq)
                      (mapc #'(lambda (*mem-max*)
                                (let ((buf (create-test-buffer 4)))
                                  (unwind-protect
                                    (let ((end (min (buffer-length buf)
                                                    (length seq))))
                                      (b/s-replace buf seq :start1 0 :end1 end
                                                           :start2 0 :end2 end)
                                      (assert (buffer-equal expected-buf buf)))
                                    (release-buffer buf))))
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
