;;;; -*- Mode: LISP; Syntax: COMMON-LISP; indent-tabs-mode: nil; coding: utf-8; show-trailing-whitespace: t -*-
;;;
;;; Copyright (C) 2005  David Lichteblau
;;;
;;; See LICENSE for details.

#+xcvb (module (:depends-on ("package")))

(in-package cl+ssl)

(defconstant +bio-type-socket+ (logior 5 #x0400 #x0100))
(defconstant +BIO_FLAGS_READ+ 1)
(defconstant +BIO_FLAGS_WRITE+ 2)
(defconstant +BIO_FLAGS_SHOULD_RETRY+ 8)
(defconstant +BIO_CTRL_FLUSH+ 11)

(cffi:defcstruct bio-method
  (type :int)
  (name :pointer)
  (bwrite :pointer)
  (bread :pointer)
  (bputs :pointer)
  (bgets :pointer)
  (ctrl :pointer)
  (create :pointer)
  (destroy :pointer)
  (callback-ctrl :pointer))

(cffi:defcstruct bio
  (method :pointer)
  (callback :pointer)
  (cb-arg :pointer)
  (init :int)
  (shutdown :int)
  (flags :int)
  (retry-reason :int)
  (num :int)
  (ptr :pointer)
  (next-bio :pointer)
  (prev-bio :pointer)
  (references :int)
  (num-read :unsigned-long)
  (num-write :unsigned-long)
  (crypto-ex-data-stack :pointer)
  (crypto-ex-data-dummy :int))

#-bio-opaque-slots
(defun make-bio-lisp-method ()
  (let ((m (cffi:foreign-alloc '(:struct bio-method))))
    (setf (cffi:foreign-slot-value m '(:struct bio-method) 'type)
    ;; fixme: this is wrong, but presumably still better than some
    ;; random value here.
    +bio-type-socket+)
    (macrolet ((slot (name)
     `(cffi:foreign-slot-value m '(:struct bio-method) ,name)))
      (setf (slot 'name) (cffi:foreign-string-alloc "lisp"))
      (setf (slot 'bwrite) (cffi:callback lisp-write))
      (setf (slot 'bread) (cffi:callback lisp-read))
      (setf (slot 'bputs) (cffi:callback lisp-puts))
      (setf (slot 'bgets) (cffi:callback lisp-gets))
      (setf (slot 'ctrl) (cffi:callback lisp-ctrl))
      (setf (slot 'create) (cffi:callback lisp-create-slots))
      (setf (slot 'destroy) (cffi:callback lisp-destroy))
      (setf (slot 'callback-ctrl) (cffi:null-pointer)))
    m))

#+bio-opaque-slots
(defun make-bio-lisp-method ()
  (let ((m (bio-meth-new (load-time-value (bio-new-index)) "lisp")))
    (bio-set-puts m  (cffi:callback lisp-puts))
    (bio-set-write m  (cffi:callback lisp-write))
    (bio-set-read m  (cffi:callback lisp-read))
    (bio-set-gets m  (cffi:callback lisp-gets))
    (bio-set-create m  (cffi:callback lisp-create-opaque))
;    (bio-set-destroy m  (cffi:callback lisp-destroy))
    (bio-set-ctrl m  (cffi:callback lisp-ctrl))
    m))

(defun bio-new-lisp ()
  (bio-new *bio-lisp-method*))


;;; "cargo cult"

;;;; Error handling in callbacks:

;;;; Catch all serious conditions and return -1 on error for reads (as
;;;; we cannot guarantee that anything was really written unless
;;;; output is finished) and number of bytes read for writes.

;;;; If read or write fails and the call was blocking, ensure that
;;;; BIO_should_retry says do not retry.

;;;; Possible improvements:
;;;; - communicate error reasons either offline (as is *socket* kept offline now) or in retry-reason variable.
;;;; - handle some specific error situations specifically (timeouts, end-of-file, no data on wire at the moment)

;;;; Rationale: Man page for BIO_meth_get_write (3) and similar states
;;;; that the callback function behave same as write etc.

;;;; Man page for BIO_read etc reads:
;;;; "(...) return either the amount of data successfully read or
;;;; written (if the return value is positive) or that no data was
;;;; successfully read or written if the result is 0 or -1. If the
;;;; return value is -2 then the operation is not implemented in the
;;;; specific BIO type. The trailing NUL is not included in the length
;;;; returned by BIO_gets()."
(cffi:defcallback lisp-write :int ((bio :pointer) (buf :pointer) (n :int))
  bio
  (handler-case
      (progn (dotimes (i n)
               (write-byte (cffi:mem-ref buf :unsigned-char i) *socket*))
             (finish-output *socket*)
             n)
    (serious-condition () -1)))

(defun clear-retry-flags (bio)
  #+bio-opaque-slots
  (bio-clear-flags bio
                   (logior +BIO_FLAGS_READ+
                           +BIO_FLAGS_WRITE+
                           +BIO_FLAGS_SHOULD_RETRY+))
  #-bio-opaque-slots
  (setf (cffi:foreign-slot-value bio '(:struct bio) 'flags)
        (logandc2 (cffi:foreign-slot-value bio '(:struct bio) 'flags)
                  (logior +BIO_FLAGS_READ+
                          +BIO_FLAGS_WRITE+
                          +BIO_FLAGS_SHOULD_RETRY+))))

#-bio-opaque-slots
(defun set-retry-read-slots (bio)
  (setf (cffi:foreign-slot-value bio '(:struct bio) 'flags)
  (logior (cffi:foreign-slot-value bio '(:struct bio) 'flags)
    +BIO_FLAGS_READ+
    +BIO_FLAGS_SHOULD_RETRY+)))


#+bio-opaque-slots
(defun set-retry-read-opaque (bio)
  (bio-set-flags bio
                 (logior +BIO_FLAGS_READ+ +BIO_FLAGS_SHOULD_RETRY+)))

(cffi:defcallback lisp-read :int ((bio :pointer) (buf :pointer) (n :int))
  bio buf n
  (let ((i 0))
    (handler-case
  (unless (or (cffi:null-pointer-p buf) (null n))
    (clear-retry-flags bio)
    (when (or *blockp* (listen *socket*))
            (setf (cffi:mem-ref buf :unsigned-char i) (read-byte *socket*))
            (incf i))
    (loop
        while (and (< i n)
                         (or (null *partial-read-p*) (listen *socket*)))
        do
    (setf (cffi:mem-ref buf :unsigned-char i) (read-byte *socket*))
    (incf i))
    i
    (when (zerop i) (set-retry-read bio)))
      (end-of-file ()
        ;; could this be part of serious condition?
        (clear-retry-flags bio)
        (setf (cffi:mem-ref buf :unsigned-char i) 0))
      (serious-condition ()
        (clear-retry-flags bio)
        ;; we could set BIO_set_retry_reason() if we defined
        ;; codes. Could be useful for timeouts, but not implemented now.
        ))
    i))

(cffi:defcallback lisp-gets :int ((bio :pointer) (buf :pointer) (n :int))
  (let ((i 0))
    (handler-case
        (unless (or (cffi:null-pointer-p buf) (null n))
          (clear-retry-flags bio)
          (when (or *blockp* (listen *socket*))
            (setf (cffi:mem-ref buf :unsigned-char i) (read-byte *socket*))
            (incf i))
          (loop
            with char
            and exit = nil
            while (and (< i n)
                       (null exit)
                       (or (null *partial-read-p*) (listen *socket*)))
            do
               (setf char (read-byte *socket*)
                     exit (= char 10))
               (unless exit
                 (setf (cffi:mem-ref buf :unsigned-char i) char)
                 (incf i))))
      (serious-condition ()
        (clear-retry-flags bio)))
    (unless (>= i n)
      (setf (cffi:mem-ref buf :unsigned-char i) 0))
    i))

(cffi:defcallback lisp-puts :int ((bio :pointer) (buf :string))
  (declare (ignore bio))
  (restart-case
      (progn
        (write-line buf (flex:make-flexi-stream *socket* :external-format :ascii))
        ;; puts is not specified to return length, but BIO expects it :(
        (1+ (length buf)))
    (serious-condition () -1)))

(cffi:defcallback lisp-ctrl :int
  ((bio :pointer) (cmd :int) (larg :long) (parg :pointer))
  bio larg parg
  (cond
    ((eql cmd +BIO_CTRL_FLUSH+) 1)
    (t
      ;; (warn "lisp-ctrl(~A,~A,~A)" cmd larg parg)
      0)))

#-bio-opaque-slots
(cffi:defcallback lisp-create-slots :int ((bio :pointer))
  (setf (cffi:foreign-slot-value bio '(:struct bio) 'init) 1)
  (setf (cffi:foreign-slot-value bio '(:struct bio) 'num) 0)
  (setf (cffi:foreign-slot-value bio '(:struct bio) 'ptr) (cffi:null-pointer))
  (setf (cffi:foreign-slot-value bio '(:struct bio) 'flags) 0)
  1)

#+bio-opaque-slots
(cffi:defcallback lisp-create-opaque :int ((bio :pointer))
  (bio-set-init bio 1)
  1)

#-bio-opaque-slots
(cffi:defcallback lisp-destroy :int ((bio :pointer))
  (cond
    ((cffi:null-pointer-p bio) 0)
    (t
      (setf (cffi:foreign-slot-value bio '(:struct bio) 'init) 0)
      (setf (cffi:foreign-slot-value bio '(:struct bio) 'flags) 0)
      1)))

;;;; Convenience macros
(defmacro with-bio-output-to-string ((bio &key (element-type ''character) (transformer '#'code-char)) &body body)
  "Evaluate BODY with BIO bound to a SSL BIO structure that writes to a
Common Lisp string.  The string is returned."
  `(let ((*socket* (flex:make-in-memory-output-stream :element-type ,element-type :transformer ,transformer))
	 (,bio (bio-new-lisp)))
     (unwind-protect
          (progn ,@body)
       (bio-free ,bio))
     (flex:get-output-stream-sequence *socket*)))

(defmacro with-bio-input-from-string ((bio string &key (transformer '#'char-code))
				      &body body)
  "Evaluate BODY with BIO bound to a SSL BIO structure that reads from
a Common Lisp STRING."
  `(let ((*socket* (flex:make-in-memory-input-stream ,string :transformer ,transformer))
	 (,bio (bio-new-lisp)))
     (unwind-protect
          (progn ,@body)
       (bio-free ,bio))))

(setf *bio-lisp-method* nil)    ;force reinit if anything changed here
