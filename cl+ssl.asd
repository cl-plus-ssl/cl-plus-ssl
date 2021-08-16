;;;; -*- Mode: LISP; Syntax: COMMON-LISP; indent-tabs-mode: nil; coding: utf-8; show-trailing-whitespace: t -*-
;;;
;;; Copyright (C) 2001, 2003  Eric Marsden
;;; Copyright (C) 2005  David Lichteblau
;;; Copyright (C) 2007  Pixel // pinterface
;;; "the conditions and ENSURE-SSL-FUNCALL are by Jochen Schmidt."
;;;
;;; See LICENSE for details.

(defpackage :cl+ssl-system
  (:use :cl :asdf))

(in-package :cl+ssl-system)

(defsystem :cl+ssl
  :description "Common Lisp interface to OpenSSL."
  :license "MIT"
  :author "Eric Marsden, Jochen Schmidt, David Lichteblau"
  :depends-on (:cl+ssl/config
               :cffi :trivial-gray-streams :flexi-streams #+sbcl :sb-posix
               #+(and sbcl win32) :sb-bsd-sockets
               :bordeaux-threads :trivial-garbage :uiop
               :usocket
               :alexandria :trivial-features)
  :serial t
  :components ((:module "src"
                :serial t
                :components
                ((:file "package")
                 (:file "reload")
                 (:file "conditions")
                 (:file "ffi")
                 (:file "ffi-buffer-all")
                 #-clisp (:file "ffi-buffer")
                 #+clisp (:file "ffi-buffer-clisp")
                 (:file "streams")
                 (:file "bio")
                 (:file "x509")
                 (:file "random")
                 (:file "context")
                 (:file "verify-hostname")))))

(defsystem :cl+ssl/config
  :depends-on (:cffi)
  :components ((:module "src"
                :serial t
                :components ((:file "config")))))
