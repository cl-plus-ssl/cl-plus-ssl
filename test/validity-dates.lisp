;;;; -*- Mode: LISP; Syntax: COMMON-LISP; indent-tabs-mode: nil; coding: utf-8; show-trailing-whitespace: t -*-

(in-package :cl+ssl.test)

(def-suite :cl+ssl.validity-dates :in :cl+ssl
  :description "Validity date tests")

(in-suite :cl+ssl.validity-dates)

(test validity-dates-google-cert
  (with-cert ("google.der" cert)
    (is (= (cl+ssl:get-not-after-time cert)
           3641760000))
    (is (= (cl+ssl:get-not-before-time cert)
           3634055286))))

