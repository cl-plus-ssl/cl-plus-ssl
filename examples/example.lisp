;;; Copyright (C) 2001, 2003  Eric Marsden
;;; Copyright (C) 2005  David Lichteblau
;;; "the conditions and ENSURE-SSL-FUNCALL are by Jochen Schmidt."
;;;
;;; See LICENSE for details.

#|
(load "example.lisp")
(ssl-test::test-https-client "www.google.com")
(ssl-test::test-https-server)
|#

(defpackage :ssl-test
  (:use :cl))
(in-package :ssl-test)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (ql:quickload '("cl+ssl" "trivial-sockets")))

(defun read-line-crlf (stream &optional eof-error-p)
  (let ((s (make-string-output-stream)))
    (loop
      for empty = t then nil
      for c = (read-char stream eof-error-p nil)
      while (and c (not (eql c #\return)))
      do
         (unless (eql c #\newline)
           (write-char c s))
      finally
         (return
           (if empty nil (get-output-stream-string s))))))

(defun test-nntps-client (&optional (host "snews.gmane.org") (port 563))
  (let* ((sock (trivial-sockets:open-stream host port
                                            :element-type '(unsigned-byte 8)))
         (nntps (cl+ssl:make-ssl-client-stream sock
                                               :external-format '(:iso-8859-1 :eol-style :lf))))
    (format t "NNTPS> ~A~%" (read-line-crlf nntps))
    (write-line "HELP" nntps)
    (force-output nntps)
    (loop :for line = (read-line-crlf nntps nil)
          :until (string-equal "." line)
          :do (format t "NNTPS> ~A~%" line))))


;; open an HTTPS connection to a secure web server and make a
;; HEAD request
(defun test-https-client (host &optional (port 443))
  (let* ((deadline (+ (get-internal-real-time)
                      (* 3 internal-time-units-per-second)))
         (socket (ccl:make-socket :address-family :internet
                                  :connect :active
                                  :type :stream
                                  :format :bivalent
                                  :remote-host host
                                  :remote-port port
                                  ;; :local-host (resolve-hostname local-host)
                                  ;; :local-port local-port
                                  :deadline deadline))
         (https
           (progn
             (cl+ssl:make-ssl-client-stream
              socket
              :unwrap-stream-p t
              :hostname host
              :external-format '(:utf-8 :eol-style :lf)))))
    (unwind-protect
         (progn
           (format https "HEAD / HTTP/1.0~%Host: ~a~%~%" host)
           (force-output https)
           (loop :for line = (read-line-crlf https nil)
                 :while line
                 :do (format t "HTTPS> ~a~%" line)
                 :while (plusp (length line))
                 ;; Empty line means headers ended.
                 ;; (Don't try to read further expecting end of stream,
                 ;; because some servers, like google.com,
                 ;; close the TCP socket without sending TLS close_notify alert,
                 ;; and OpenSSL in this case signals an "Unexpected EOF"
                 ;; error if we try to read.
                 ;; Such servers expect HTTP clients to use the HTTP
                 ;; protocol format to determine how many bytes to read,
                 ;; instead of relying on the connection termination.)
                 ))
      (close https))))

;; Start a simple HTTPS server.
;;
;; Simple self-signed certificate and private key can be generated with
;;
;;    openssl req -new -nodes -x509 -days 365 -subj / -keyout private-key.pem -outform PEM -out certificate.pem
;;
;; For "real" certificates, you can use, for exammple, https://letsencrypt.org,
;; or see the mod_ssl documentation at <URL:http://www.modssl.org/>
;; (like http://www.modssl.org/docs/2.8/ssl_faq.html)
;;
;; Query the server:
;;
;;   curl --insecure https://localhost:8080/foobar
;;
;; Stop the server:
;;
;;   curl --insecure https://localhost:8080/quit
;;
;; (the --insecure is for self-signed certificate)
;;
;; If you query this server started with a self-signed certificate
;; from browser, first time the browser will show a "Security Risk"
;; error page and the server will break with "bad certificate alert"
;; error. Then you can add a browser security exception
;; from the "Security Risk" page, start the server again and re-open the URL.
(defun test-https-server
    (&key (port 8080)
       (cert "/home/anton/prj/cl+ssl/cl-plus-ssl/examples/certificate.pem")
       (key "/home/anton/prj/cl+ssl/cl-plus-ssl/examples/private-key.pem"))
  (format t "~&SSL server listening on port ~d~%" port)
  (trivial-sockets:with-server (server (:port port))
    (loop
      (let* ((socket (trivial-sockets:accept-connection
                      server
                      :element-type '(unsigned-byte 8)))
             (client (cl+ssl:make-ssl-server-stream
                      socket
                      :external-format '(:iso-8859-1 :eol-style :lf)
                      :certificate cert
                      :key key))
             (quit nil))
        (unwind-protect
             (progn
               (loop :for line = (read-line-crlf client nil)
                     :while (> (length line) 1)
                     :do (format t "HTTPS> ~a~%" line)
                         (when (search "/quit" line)
                           (setf quit t)))
               (format client "HTTP/1.0 200 OK~%")
               (format client "Server: cl+ssl/examples/example.lisp/1.1~%")
               (format client "Content-Type: text/plain~%")
               (terpri client)
               (format client "~:[G'day~;Bye~] at ~A!~%"
                       quit
                       (multiple-value-list (get-decoded-time)))
               (format client "CL+SSL running in ~A ~A~%"
                       (lisp-implementation-type)
                       (lisp-implementation-version))
               (when quit (return)))
          (close client))))))
