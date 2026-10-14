;;;; This should only be loaded/used if there is no way for the user
;;;; to get his/her Lisp process to create a second thread. If there is
;;;; any conceivable way for a second thread to be created in the Lisp
;;;; implementation, then this file should not be loaded.

(in-package :cl+ssl)

(defun threading-initialize ())

(defmacro threading-with-global-lock-held (&body body)
  (cons 'progn body))
