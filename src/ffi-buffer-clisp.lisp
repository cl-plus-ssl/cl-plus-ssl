;;;; -*- Mode: LISP; Syntax: COMMON-LISP; indent-tabs-mode: nil; coding: utf-8; show-trailing-whitespace: t -*-
;;;
;;; Copyright (C) contributors as per cl+ssl git history
;;;
;;; See LICENSE for details.

;;;; CLISP speedup comments by Pixel / pinterface, 2007,
;;;; copied from https://code.kepibu.org/cl+ssl/
;;;;
;;;; ## Speeding Up clisp
;;;; cl+ssl has some serious speed issues on CLISP. For small requests,
;;;; it's not enough to worry about, but on larger requests the speed
;;;; issue can mean the difference between a 15 second download and a 15
;;;; minute download. And that just won't do!
;;;;
;;;; ### What Makes cl+ssl on clisp so slow?
;;;; On clisp, cffi's with-pointer-to-vector-data macro uses copy-in,
;;;; copy-out semantics, because clisp doesn't offer a with-pinned-object
;;;; facility or some other way of getting at the pointer to a simple-array.
;;;; Very sad, I know. In addition to being a leaky abstraction, wptvd is really slow.
;;;;
;;;; ### How to Speed Things Up?
;;;; The simplest thing that can possibly work: break the abstraction.
;;;; I introduce several new functions (buffer-length, buffer-elt, etc.)
;;;; and use those wherever an ssl-stream-*-buffer happens to be used,
;;;; in place of the corresponding sequence functions.
;;;; Those buffer-* functions operate on clisp's ffi:pointer objects,
;;;; resulting in a tremendous speedup--and probably a memory leak or two.
;;;;
;;;; ### This Is Not For You If...
;;;; While I've made an effort to ensure this patch doesn't break other
;;;; implementations, if you have code which relies on ssl-stream-*-buffer
;;;; returning an array you can use standard CL functions on, it will break
;;;; on clisp under this patch. But you weren't relying on cl+ssl
;;;; internals anyway, now were you?

#|
2025-11-22
Comments:
1. MEMORY-AS copies. So the 60x speedup from 15 minutes to 15 seconds for
   large downloads could not have been due to avoiding copying the buffer
   because this S/B-REPLACE also copies the buffer (just once instead of
   twice as the original wptvd would do). Such a large speedup was likely
   due to copying via a single foreign call to MEMORY-AS instead of one
   foreign call per element via %MEM-REF.
2. streams.lisp's STREAM-LISTEN and STREAM-READ-BYTE would however indeed
   have been sped up 100 or 1000x due to copying only one byte instead of
   the whole buffer.
3. The solution above claims to break wptvd's abstraction. In fact, wptvd
   was not abstract enough and the solution increases (and improves) its
   abstraction. Making the buffer into a proper abstract data type so users
   of its instances don't pry into its internal implementation improves
   the wptvd abstraction. ffi-buffer.lisp and ffi-buffer-clisp.lisp should
   be moved into cffi, replacing what cffi already has.
Improvements: In this updated version of the file:
- All memory leaks are fixed.
- All array boundary miscalculations, which would cause crashes, are fixed.
- S/B-REPLACE and B/S-REPLACE now require O(1) memory as expected of them.
- Data copying is reduced.
|#

(in-package :cl+ssl)

(defclass clisp-ffi-buffer ()
  ((size
    :initarg :size
    :accessor clisp-ffi-buffer-size)
   (pointer
    :initarg :pointer
    :accessor clisp-ffi-buffer-pointer)))

(defun make-buffer (size)
  (make-instance 'clisp-ffi-buffer
                 :size size
                 :pointer (cffi-sys:%foreign-alloc size)))

(defun release-buffer (buf)
  (let ((addr (clisp-ffi-buffer-pointer buf)))
    (when (ffi:validp addr)
        (ffi:foreign-free addr)
        (setf (ffi:validp addr) nil))))

(defun buffer-length (buf)
  (clisp-ffi-buffer-size buf))

(defun buffer-elt (buf index)
  (ffi:memory-as (clisp-ffi-buffer-pointer buf) 'ffi:uint8 index))
(defun set-buffer-elt (buf index val)
  (setf (ffi:memory-as (clisp-ffi-buffer-pointer buf) 'ffi:uint8 index) val))
(defsetf buffer-elt set-buffer-elt)

(defconstant +mem-max+ 1024 "so *-REPLACE require the expected O(1) memory")

(defun s/b-replace (seq buf &key (start1 0) end1 (start2 0) end2)
  (when (null end1) (setf end1 (length seq)))
  (when (null end2) (setf end2 (buffer-length buf)))
  (let ((n (min (- end1 start1) (- end2 start2))))
    (do* ((remainder n (- remainder m))
          (s1 start1 (+ s1 m))
          (s2 start2 (+ s2 m))
          (m (min remainder +mem-max+) (min remainder +mem-max+)))
         ((zerop m) seq)
      (replace
        seq
        (ffi:memory-as (clisp-ffi-buffer-pointer buf)
                       (ffi:parse-c-type `(ffi:c-array ffi:uint8 ,m))
                       s2)
        :start1 s1))))

(defun b/s-replace (buf seq &key (start1 0) end1 (start2 0) end2)
  (labels ((replace-buf (s1 count vec s2)
             "replaces exactly COUNT elts of BUF starting at S1 with elts of
              VEC starting at S2"
             (declare (type vector vec))
             (setf
               (ffi:memory-as (clisp-ffi-buffer-pointer buf)
                              (ffi:parse-c-type `(ffi:c-array ffi:uint8 ,count))
                              s1)
               (cond ((= count (length vec)) (assert (zerop s2)) vec)
                     (t (make-array count :element-type (array-element-type vec)
                                          :displaced-to vec
                                          :displaced-index-offset s2))))))
    (when (null end1) (setf end1 (buffer-length buf)))
    (when (null end2) (setf end2 (length seq)))
    (let ((n (min (- end1 start1) (- end2 start2))))
      (cond ((typep seq 'vector) (replace-buf start1 n seq start2))
            (t
             (assert (consp seq))
             (let ((vec2 (make-array (min n +mem-max+)
                                     :element-type '(unsigned-byte 8)))
                   (seq2 (nthcdr start2 seq)))
               (do* ((remainder n (- remainder m))
                     (s1 start1 (+ s1 m))
                     (m (min remainder +mem-max+) (min remainder +mem-max+)))
                    ((zerop m))
                 (dotimes (i m)
                   (setf (aref vec2 i) (car seq2)
                         seq2 (cdr seq2)))
                 (replace-buf s1 m vec2 0)))))))
  buf)

(defmacro with-pointer-to-vector-data ((ptr buf) &body body)
  `(let ((,ptr (clisp-ffi-buffer-pointer ,buf)))
    ,@body))
