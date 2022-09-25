;;; Copyright (C) 2001, 2003  Eric Marsden
;;; Copyright (C) 2005  David Lichteblau
;;; "the conditions and ENSURE-SSL-FUNCALL are by Jochen Schmidt."
;;;
;;; See LICENSE for details.

#|
;; Assuming Quicklisp is installed.
(load "example.lisp")

(tls-example::test-https-client "www.google.com")

;; generate key and cert as explained in the test-https-server comments
(tls-example::test-https-server :key "/path/to/private-key.pem"
                                :cert "/path/to/certificate.pem"
                                :passphrase "1234")
;; test the server with curl or web browser as explained in the comments

(tls-example::test-nntp-client)
|#

(defpackage :tls-example
  (:use :cl))
(in-package :tls-example)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (ql:quickload '("cl+ssl" "trivial-sockets")))


;; Open an HTTPS connection to a secure web server and make a
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
              :hostname host
              :external-format '(:utf-8 :eol-style :crlf)))))
    (unwind-protect
         (progn
           (format https "HEAD / HTTP/1.0~%Host: ~a~%~%" host)
           (force-output https)
           (loop :for line = (read-line https nil)
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
;; Simple self-signed certificate and private key encrypted with
;; passphrase "1234" can be generated with
;;
;;     openssl req -new -x509 -days 365 -subj / -keyout private-key.pem -passout pass:1234 -out certificate.pem -outform PEM
;;
;; For "real" certificates, you can use, for exammple, https://letsencrypt.org,
;; or see the mod_ssl documentation at <URL:http://www.modssl.org/>
;; (like http://www.modssl.org/docs/2.8/ssl_faq.html)
;;
;; Query the server:
;;
;;     curl --insecure https://localhost:8080/foobar
;;
;; Stop the server:
;;
;;     curl --insecure https://localhost:8080/quit
;;
;; (the --insecure is for self-signed certificate)
;;
;; If you query this server started with a self-signed certificate
;; from browser, first time the browser will show a "Security Risk"
;; error page and the server will break with "bad certificate alert"
;; error. Then you can add a browser security exception
;; from the "Security Risk" page, start the server again and re-open the URL.
(defun test-https-server (&key
                            (port 8080)
                            (cert "certificate.pem")
                            (key "private-key.pem")
                            (passphrase "1234"))
  (format t "~&SSL server listening on port ~d~%" port)
  (trivial-sockets:with-server (server (:port port))
    (loop
      (let* ((socket (trivial-sockets:accept-connection
                      server
                      :element-type '(unsigned-byte 8)))
             (client (cl+ssl:make-ssl-server-stream
                      socket
                      :external-format '(:utf-8 :eol-style :crlf)
                      :certificate cert
                      :key key
                      :password passphrase))
             (quit nil))
        (unwind-protect
             (progn
               ;; Read and log the request with its headers
               (loop :for line = (read-line client nil)
                     :while line
                     :do (format t "HTTPS> ~a~%" line)
                         (when (search "/quit" line)
                           (setf quit t))
                     :while (plusp (length line)))
               ;; Write a response
               (format client "HTTP/1.0 200 OK~%")
               (format client "Server: cl+ssl/examples/example.lisp~%")
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


;; Connect to an NNTP server, upgrade connection to TLS
;; using the STARTTLS command, then execute the HELP
;; command. Log the server responses.
;;
;; (We use STARTTLS instead of connecting to a dedicated
;; TLS port, becuase Gmane does not seem to have a dedicated
;; TLS port).
(defun test-nntps-client (&optional (host "news.gmane.io") (port 119))
  (let* ((sock (trivial-sockets:open-stream host port
                                            :element-type '(unsigned-byte 8)))
         (plain-text (flex:make-flexi-stream
                      sock
                      :external-format '(:utf-8 :eol-style :crlf))))
    (format t "NNTPS> ~A~%" (read-line plain-text))
    (format sock "STARTTLS~%")
    (force-output sock)
    ;; In this example we don't look at the server
    ;; respone line to the STARTLS command,
    ;; assuming it is successfull (status code 382);
    ;; just log it and start TLS session.
    (format t "NNTPS> ~A~%" (read-line plain-text))
    (let ((nntps (cl+ssl:make-ssl-client-stream
                  sock
                  :hostname host
                  :external-format '(:utf-8 :eol-style :crlf))))
      (write-line "HELP" nntps)
      (force-output nntps)
      (loop :for line = (read-line nntps nil)
            :while line
            :do (format t "NNTPS> ~A~%" line)
            :until (string-equal "." line)))))
