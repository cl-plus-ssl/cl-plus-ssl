#!/bin/bash

# safe mode
set -euo pipefail

# verbose
set -v

ros -e '(when (uiop:getenvp "READTABLE_CASE_INVERT")
          (format t "changing readtable-case to :invert~%")
          (setq *readtable*
                (let ((rt (copy-readtable)))
                  (setf (readtable-case rt) :invert)
                  rt)))' \
    -e '(progn
          (format t "(lisp-implementation-type): ~A~%" (lisp-implementation-type))
          (format t "(lisp-implementation-version): ~A~%" (lisp-implementation-version))
          (format t "*features*: ~A~%" *features*)
          (format t "(asdf:asdf-version): ~A~%" (asdf:asdf-version)))' \
    -e '#+abcl
        (progn
           (format t "Loading abcl-asdf and switching maven repo URL to HTTPS (see https://github.com/armedbear/abcl/issues/151)~%")
           (require :abcl-contrib)
           (format t "abcl-contrib loaded...~%")
           (require :abcl-asdf)
           (format t "abcl-asdf loaded...~%")
           (format t "*features*: ~A~%" *features*)
           (setf (symbol-value (read-from-string "abcl-asdf::*default-repository*"))
                 "https://repo1.maven.org/maven2/")
           (format t "abcl-asdf::*default-repository* assigned the HTTPS URL.~%"))' \
    -e '(ql:quickload :cffi)' \
    -e '(format t "cffi loaded.~%")' \
    -e '(ql:quickload :cl+ssl/config)' \
    -e '(format t "cl+ssl/config loaded.~%")' \
    -e '(let ((lib-load-mode (uiop:getenvp "LIB_LOAD_MODE")))
          (cond ((string= "new" lib-load-mode)
                 (cl+ssl/config:define-libcrypto-path "test/run-on-many-lisps-and-openssls/openssl-releases/bin/'$OPENSSL-${BITS}bit'/lib/libcrypto.so")
                 (cl+ssl/config:define-libssl-path "test/run-on-many-lisps-and-openssls/openssl-releases/bin/'$OPENSSL-${BITS}bit'/lib/libssl.so"))
                ((string= "old" lib-load-mode)
                 (cffi:load-foreign-library "test/run-on-many-lisps-and-openssls/openssl-releases/bin/'$OPENSSL-${BITS}bit'/lib/libcrypto.so")
                 (format t "libcrypto.so loaded.~%")
                 (cffi:load-foreign-library "test/run-on-many-lisps-and-openssls/openssl-releases/bin/'$OPENSSL-${BITS}bit'/lib/libssl.so")
                 (format t "libssl.so loaded.~%")
                 (pushnew :cl+ssl-foreign-libs-already-loaded *features*))
                (t
                 (format t "Unexpected LIB_LOAD_MODE value: ~A~%" lib-load-mode)
                 (uiop:quit 1))))' \
    -e '(ql:quickload :cl+ssl) ;; load cl+ssl separately from cl+ssl.test only because cl+ssl.test can not be loaded in the :invert readtable-case due to its dependency ironclad, as of 2019-10-20' \
    -e '(format t "cl+ssl loaded.~%")' \
    -e '(when (uiop:getenvp "READTABLE_CASE_INVERT")
          (format t "restoring readtable-case to :upcase before loading cl+ssl.test~%")
          (setf (readtable-case *readtable*) :upcase))' \
    -e '(ql:quickload :cl+ssl.test)' \
    -e '(format t "(cl+ssl::compat-openssl-version): ~A~%" (cl+ssl::compat-openssl-version))' \
    -e '(let ((results
                  #+ sbcl
                  (coveralls:with-coveralls (:exclude "test")
                     (5am:run :cl+ssl))
                  #- sbcl
                  (5am:run :cl+ssl)
                  ))
          (5am:explain! results)
          #+(and abcl cl+ssl-foreign-libs-already-loaded)
          (let* ((expected-failures (quote (cl+ssl.test::bio-gets
                                            cl+ssl.test::bio-read
                                            cl+ssl.test::bio-write-puts
                                            cl+ssl.test::expired.file-descriptor-bio
                                            cl+ssl.test::expired.lisp-bio
                                            cl+ssl.test::fingerprint-google-cert
                                            cl+ssl.test::wrong.host.file-descriptor-bio
                                            cl+ssl.test::wrong.host.lisp-bio)))
                (failed-test-names (mapcar (lambda (result)
                                              (5am::name (5am::test-case result)))
                                            (remove-if-not (quote 5am::test-failure-p)
                                                           results))))
            (if (set-exclusive-or expected-failures
                                  failed-test-names)
                (progn
                  (format t "~%ABCL: expected failures on Travis CI: ~S, actual failures: ~S~%"
                          expected-failures
                          failed-test-names)
                  (uiop:quit 1))
                (format t "ABCL failed some tests as expected on Travis CI with :cl+ssl-foreign-libs-already-loaded: ~S~%"
                        expected-failures)))
          #-(and abcl cl+ssl-foreign-libs-already-loaded)
          (unless (5am:results-status results)
            (uiop:quit 1)))'
