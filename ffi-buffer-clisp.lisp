(in-package :cl+ssl)

(defun make-buffer (size)
  (cffi-sys:%foreign-alloc size))

(defun buffer-length (buf)
  (declare (ignore buf))
  +initial-buffer-size+)

(defun buffer-elt (buf index)
  (ffi:memory-as buf 'ffi:uint8 index))
(defun set-buffer-elt (buf index val)
  (setf (ffi:memory-as buf 'ffi:uint8 index) val))
(defsetf buffer-elt set-buffer-elt)

(declaim
 (inline calc-buf-end))

;; to calculate non NIL value of the buffer end index
(defun calc-buf-end (buf-start vec vec-start vec-end)
  (+ buf-start 
     (- (or vec-end (length vec))
        vec-start)))

(defun v/b-replace (vec buf &key (start1 0) end1 (start2 0) end2)
  (when (null end2)
    (setf end2 (calc-buf-end start2 vec start1 end1)))
  (replace
   vec
   (ffi:memory-as buf (ffi:parse-c-type `(ffi:c-array ffi:uint8 ,(- end2 start2))) start2)
   :start1 start1
   :end1 end1))

(defun b/v-replace (buf vec &key (start1 0) end1 (start2 0) end2)
  (when (null end1)
    (setf end1 (calc-buf-end start1 vec start2 end2)))
  (setf
   (ffi:memory-as buf (ffi:parse-c-type `(ffi:c-array ffi:uint8 ,(- end1 start1))) start1)
   (subseq vec start2 end2)))

(defmacro with-pointer-to-vector-data ((ptr buf) &body body)
  `(let ((,ptr ,buf))
    ,@body))
