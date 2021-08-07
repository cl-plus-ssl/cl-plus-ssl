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

(unless *bio-methods-have-opaque-slots*
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
    (crypto-ex-data-dummy :int)))

(defun make-bio-lisp-method-using-slots ()
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
      (setf (slot 'bgets) (cffi:null-pointer))
      (setf (slot 'ctrl) (cffi:callback lisp-ctrl))
      (setf (slot 'create) (cffi:callback lisp-create-slots))
      (setf (slot 'destroy) (cffi:callback lisp-destroy))
      (setf (slot 'callback-ctrl) (cffi:null-pointer)))
    m))

(defun make-bio-lisp-method-opaque ()
  (let ((m (bio-meth-new (load-time-value (bio-new-index)) "lisp")))
    (bio-set-puts m  (cffi:callback lisp-puts))
    (bio-set-write m  (cffi:callback lisp-write))
    (bio-set-read m  (cffi:callback lisp-read))
    (bio-set-gets m  (cffi:callback lisp-gets))
    (bio-set-create m  (cffi:callback lisp-create-opaque))
;    (bio-set-destroy m  (cffi:callback lisp-destroy))
    (bio-set-ctrl m  (cffi:callback lisp-ctrl))
    m))

(defun make-bio-lisp-method ()
  (if *bio-methods-have-opaque-slots*
      (make-bio-lisp-method-opaque)
      (make-bio-lisp-method-using-slots)))

(defun bio-new-lisp ()
  (bio-new *bio-lisp-method*))


;;; "cargo cult"

(cffi:defcallback lisp-write :int ((bio :pointer) (buf :pointer) (n :int))
  bio
  (dotimes (i n)
    (write-byte (cffi:mem-ref buf :unsigned-char i) *socket*))
  (finish-output *socket*)
  n)

(defun clear-retry-flags (bio)
  (if *bio-methods-have-opaque-slots*
      (bio-clear-flags bio
                       (logior +BIO_FLAGS_READ+
                               +BIO_FLAGS_WRITE+
                               +BIO_FLAGS_SHOULD_RETRY+))
      (setf (cffi:foreign-slot-value bio '(:struct bio) 'flags)
            (logandc2 (cffi:foreign-slot-value bio '(:struct bio) 'flags)
                      (logior +BIO_FLAGS_READ+
                              +BIO_FLAGS_WRITE+
                              +BIO_FLAGS_SHOULD_RETRY+)))))

(defun set-retry-read-slots (bio)
  (setf (cffi:foreign-slot-value bio '(:struct bio) 'flags)
  (logior (cffi:foreign-slot-value bio '(:struct bio) 'flags)
    +BIO_FLAGS_READ+
    +BIO_FLAGS_SHOULD_RETRY+)))


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
    #+(or)
    (when (zerop i) (set-retry-read bio)))
      (end-of-file ()
        (setf (cffi:mem-ref buf :unsigned-char i) 0)))
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
      (end-of-file ()))
    (unless (>= i n)
      (setf (cffi:mem-ref buf :unsigned-char i) 0))
    i))

(cffi:defcallback lisp-puts :int ((bio :pointer) (buf :string))
  (declare (ignore bio))
  (write-line buf (flex:make-flexi-stream *socket* :external-format :ascii))
  ;; puts is not specified to return length, but BIO expects it :(
  (1+ (length buf)))

(cffi:defcallback lisp-ctrl :int
  ((bio :pointer) (cmd :int) (larg :long) (parg :pointer))
  bio larg parg
  (cond
    ((eql cmd +BIO_CTRL_FLUSH+) 1)
    (t
      ;; (warn "lisp-ctrl(~A,~A,~A)" cmd larg parg)
      0)))

(cffi:defcallback lisp-create-slots :int ((bio :pointer))
  (setf (cffi:foreign-slot-value bio '(:struct bio) 'init) 1)
  (setf (cffi:foreign-slot-value bio '(:struct bio) 'num) 0)
  (setf (cffi:foreign-slot-value bio '(:struct bio) 'ptr) (cffi:null-pointer))
  (setf (cffi:foreign-slot-value bio '(:struct bio) 'flags) 0)
  1)

(cffi:defcallback lisp-create-opaque :int ((bio :pointer))
  (bio-set-init bio 1)
  1)

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
