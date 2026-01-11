;;;; -*- Mode: LISP; Syntax: COMMON-LISP; indent-tabs-mode: nil; coding: utf-8; show-trailing-whitespace: t -*-
;;;
;;; Copyright (C) contributors as per cl+ssl git history
;;;
;;; See LICENSE for details.

(eval-when (:compile-toplevel)
  (declaim
   (optimize (speed 3) (space 1) (safety 1) (debug 0) (compilation-speed 0))))

(in-package :cl+ssl)

(defvar *locks*)

;; zzz as of early 2011, bxthreads is totally broken on SBCL wrt. explicit
;; locking of recursive locks.  with-recursive-lock works, but acquire/release
;; don't.  Hence we use non-recursize locks here (but can use a recursive
;; lock for the global lock).

(cffi:defcallback locking-callback :void
    ((mode :int)
     (n :int)
     (file :pointer) ;; could be (file :string), but we don't use FILE, so avoid the conversion
     (line :int))
  (declare (ignore file line))
  ;; (assert (logtest mode (logior +CRYPTO-READ+ +CRYPTO-WRITE+)))
  (let ((lock (svref *locks* n)))
    (cond
      ((logtest mode +CRYPTO-LOCK+)
       (bt:acquire-lock lock))
      ((logtest mode +CRYPTO-UNLOCK+)
       (bt:release-lock lock))
      (t
       (error "fell through")))))

(defvar *threads* (trivial-garbage:make-weak-hash-table :weakness :key))
(defvar *thread-counter* 0)

(defparameter *global-lock*
  (bt:make-recursive-lock "SSL initialization"))

;; zzz BUG: On a 32-bit system and under non-trivial load, this counter
;; is likely to wrap in less than a year.
(cffi:defcallback threadid-callback :unsigned-long ()
  (bt:with-recursive-lock-held (*global-lock*)
    (let ((self (bt:current-thread)))
      (or (gethash self *threads*)
          (setf (gethash self *threads*)
                (incf *thread-counter*))))))

(defun threading-initialize ()
    (setf *locks* (let ((result (make-array (crypto-num-locks))))
                    (dotimes (i (length result) result)
                      (setf (svref result i) (bt:make-lock)))))
    (crypto-set-locking-callback (cffi:callback locking-callback))
    (crypto-set-id-callback (cffi:callback threadid-callback)))

(defmacro threading-with-global-lock-held (&body body)
  `(bt:with-recursive-lock-held (*global-lock*)
     ,@body))
