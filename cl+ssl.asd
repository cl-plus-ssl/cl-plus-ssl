;;; -*- mode: lisp -*-
;;;
;;; Copyright (C) 2001, 2003  Eric Marsden
;;; Copyright (C) 2005  David Lichteblau
;;; "the conditions and ENSURE-SSL-FUNCALL are by Jochen Schmidt."
;;;
;;; See LICENSE for details.

(defpackage :cl+ssl-system
  (:use :cl :asdf)
  (:export #:*libssl-pathname*))

(in-package :cl+ssl-system)

(defparameter *libssl-pathname* "/usr/lib/libssl.so")

(defsystem :cl+ssl
  :depends-on (:cffi :trivial-gray-streams)
  :serial t
  :components
   ((:file "reload")
    (:file "package")
    (:file "conditions")
    (:file "ffi")
    (:file "streams")
    (:file "bio")))
