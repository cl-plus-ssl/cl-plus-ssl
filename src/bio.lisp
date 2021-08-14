;;;; -*- Mode: LISP; Syntax: COMMON-LISP; indent-tabs-mode: nil; coding: utf-8; show-trailing-whitespace: t -*-
;;;
;;; Copyright (C) 2005  David Lichteblau
;;; Copyright (C) 2021  Tomas Zellerin (zellerin@gmail.com, https://github.com/zellerin)
;;; Copyright (C) 2021  Anton Vodonosov (avodonosov@yandex.ru, https://github.com/avodonosov)
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
  (unless *bio-lisp-method* (initialize))
  (let ((new (bio-new *bio-lisp-method*)))
    (if (or (null new) (cffi:null-pointer-p new))
        (error "Cannot create bio method: ~a"
               (cl+ssl::err-error-string (cl+ssl::err-get-error) (cffi:null-pointer)))
        new)))


;;; Error handling for all the defcallback's:
;;;
;;; We want to avoid non-local exits across C stack,
;;; as CFFI tutorial recommends:
;;; https://common-lisp.net/project/cffi/manual/html_node/Tutorial_002dCallbacks.html.
;;;
;;; In cl+ssl this means the following nested calls:
;;;
;;;   1) Lisp: cl+ssl stream user code ->
;;;   2) C: OpenSSL C functions ->
;;;   3) Lisp: BIO implementation function
;;;        signals error and the controls is passe
;;;        to 1), without proper C cleanup.
;;;
;;; Therefore our BIO implementation functions catch all unexpected
;;; serious-conditions, arrange for BIO_should_retry
;;; to say "do not retry", and return -1.
;;;
;;; We could try to indicate the real number of bytes read / written -
;;; the documentation of BIO_read and friends just says return byte
;;; number without making any special case for error:
;;;
;;; "(...) return either the amount of data successfully read or
;;; written (if the return value is positive) or that no data was
;;; successfully read or written if the result is 0 or -1. If the
;;; return value is -2 then the operation is not implemented in the
;;; specific BIO type. The trailing NUL is not included in the length
;;; returned by BIO_gets().
;;;
;;; But let's not complicate the implementation, esp. taking into
;;; account that we don't know how many bytes the low level
;;; Lisp writing function has really written before signalling
;;; the condition. Our main goal is to avoid crossing C stack,
;;; and we only consider unexpected errors here.
;;;
;;; TODO: communicate error reasons to users of cl+ssl streams.
;;;    Possible approaches
;;;      - introduce a dynamic variable *bio-error*
;;;        (similar to the *socket*), set this value when our
;;;        BIO method fails, and use this value by when creating
;;;        a condition instance in ssl-signal-error
;;;      - Use the OpenSSL error facility, see ERR_raise_data.

(cffi:defcallback lisp-write :int ((bio :pointer) (buf :pointer) (n :int))
  bio
  (handler-case
      (progn (dotimes (i n)
               (write-byte (cffi:mem-ref buf :unsigned-char i) *socket*))
             (finish-output *socket*)
             n)
    (serious-condition ()
      (clear-retry-flags bio)
      -1)))

#-bio-opaque-slots
(defun clear-retry-flags (bio)
  (setf (cffi:foreign-slot-value bio '(:struct bio) 'flags)
        (logandc2 (cffi:foreign-slot-value bio '(:struct bio) 'flags)
                  (logior +BIO_FLAGS_READ+
                          +BIO_FLAGS_WRITE+
                          +BIO_FLAGS_SHOULD_RETRY+))))

#+bio-opaque-slots
(defun clear-retry-flags (bio)
  (bio-clear-flags bio
                   (logior +BIO_FLAGS_READ+
                           +BIO_FLAGS_WRITE+
                           +BIO_FLAGS_SHOULD_RETRY+)))

#-bio-opaque-slots
(defun set-retry-read (bio)
  (setf (cffi:foreign-slot-value bio '(:struct bio) 'flags)
  (logior (cffi:foreign-slot-value bio '(:struct bio) 'flags)
    +BIO_FLAGS_READ+
    +BIO_FLAGS_SHOULD_RETRY+)))


#+bio-opaque-slots
(defun set-retry-read (bio)
  (bio-set-flags bio
                 (logior +BIO_FLAGS_READ+ +BIO_FLAGS_SHOULD_RETRY+)))

(cffi:defcallback lisp-read :int ((bio :pointer) (buf :pointer) (n :int))
  bio buf n
  (handler-case
      (let ((i 0))
        (handler-case
            (progn
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
              (when (zerop i) (set-retry-read bio)))
          (end-of-file ()
            ;; do nothing,  will just return the number of bytes read so far
            ))
        i)
    (serious-condition ()
      (clear-retry-flags bio)
      -1)))

(cffi:defcallback lisp-gets :int ((bio :pointer) (buf :pointer) (n :int))
  (handler-case
      (let ((i 0)
            (max-chars (1- n)))
        (clear-retry-flags bio)
        (handler-case
            (when (> max-chars 0)
              (when (or *blockp* (listen *socket*))
                (setf (cffi:mem-ref buf :unsigned-char i) (read-byte *socket*))
                (incf i))
              (loop
                 with char
                 and exit = nil
                 while (and (< i max-chars)
                            (null exit)
                            (or (null *partial-read-p*) (listen *socket*)))
                 do
                   (setf char (read-byte *socket*)
                         exit (= char 10))
                   (setf (cffi:mem-ref buf :unsigned-char i) char)
                   (incf i)))
          (end-of-file ()
            ;; do nothing - this just aborts the lookp
            ))
        (setf (cffi:mem-ref buf :unsigned-char i) 0)
        i)
    (serious-condition ()
      (clear-retry-flags bio)
      -1)))

(cffi:defcallback lisp-puts :int ((bio :pointer) (buf :string))
  (declare (ignore bio))
  (restart-case
      (progn
        (write-line buf (flex:make-flexi-stream *socket* :external-format :ascii))
        ;; puts is not specified to return length, but BIO expects it :(
        (1+ (length buf)))
    (serious-condition ()
      (clear-retry-flags bio)
      -1)))

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
