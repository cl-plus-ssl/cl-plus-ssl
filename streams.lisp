;;; Copyright (C) 2001, 2003  Eric Marsden
;;; Copyright (C) 2005  David Lichteblau
;;; "the conditions and ENSURE-SSL-FUNCALL are by Jochen Schmidt."
;;;
;;; See LICENSE for details.

(declaim
 (optimize (speed 3) (space 1) (safety 1) (debug 0) (compilation-speed 0)))

(in-package :cl+ssl)

(defconstant +initial-buffer-size+ 2048)

(defclass ssl-stream
    (fundamental-binary-input-stream
     fundamental-binary-output-stream
     fundamental-character-input-stream
     fundamental-character-output-stream
     trivial-gray-stream-mixin)
  ((ssl-stream-socket
    :initarg :socket
    :accessor ssl-stream-socket)
   (handle
    :initform nil
    :accessor ssl-stream-handle)
   (io-buffer
    :initform (cffi-sys::make-shareable-byte-vector +initial-buffer-size+)
    :accessor ssl-stream-io-buffer)))

(defmethod print-object ((object ssl-stream) stream)
  (print-unreadable-object (object stream :type t)
    (format stream "for ~A" (ssl-stream-socket object))))

(defclass ssl-server-stream (ssl-stream) 
  ((certificate
    :initarg :certificate
    :accessor ssl-stream-certificate)
   (key
    :initarg :key
    :accessor ssl-stream-key)))


;;; binary stream implementation
;;;
(defmethod close ((stream ssl-stream) &key abort)
  (declare (ignore abort))
  (ssl-free (ssl-stream-handle stream))
  (close (ssl-stream-socket stream)))

(defmethod stream-read-byte ((stream ssl-stream))
  (let ((buf (ssl-stream-io-buffer stream)))
    (handler-case
        (cffi-sys::with-pointer-to-vector-data (ptr buf)
          (ensure-ssl-funcall (ssl-stream-socket stream)
                              (ssl-stream-handle stream)
                              #'ssl-read
			      5.5
                              (ssl-stream-handle stream)
                              ptr
			      1)
          (elt buf 0))
      ;; SSL_read returns 0 on end-of-file
      (ssl-error-zero-return ()
        :eof))))

(defmethod stream-write-byte ((stream ssl-stream) b)
  (let ((buf (ssl-stream-io-buffer stream))
        (handle (ssl-stream-handle stream))
        (socket (ssl-stream-socket stream)))
    (setf (elt buf 0) b)
    (cffi-sys::with-pointer-to-vector-data (ptr buf)
      (ensure-ssl-funcall socket handle #'ssl-write 0.5 handle ptr 1)))
  b)

(defmethod stream-write-sequence
    ((stream ssl-stream) (thing array)
     &optional (start 0) (end (length thing)))
  (check-type thing (simple-array (unsigned-byte 8) (*)))
  (let ((buf (ssl-stream-io-buffer stream))
        (handle (ssl-stream-handle stream))
	(socket (ssl-stream-socket stream))
	(length (- end start)))
    (when (> length (length buf))
      (setf buf (cffi-sys::make-shareable-byte-vector (- end start)))
      (setf (ssl-stream-io-buffer stream) buf))
    ;; unfortunately, we cannot count on being able to use THING as an
    ;; argument to WITH-POINTER-TO-VECTOR-DATA, so we need to copy all data:
    (replace buf thing :start2 start :end2 end)
    (cffi-sys::with-pointer-to-vector-data (ptr buf)
      (ensure-ssl-funcall socket handle #'ssl-write 0.5 handle ptr length))))


;;; minimal character stream implementation
;;; no support for external formats, no support for unread-char
;;;
(defmethod stream-read-char ((stream ssl-stream))
  (let ((b (stream-read-byte stream)))
    (if (eql b :eof)
	:eof
	(code-char b))))

(defmethod stream-write-char ((stream ssl-stream) char)
  (stream-write-byte stream (char-code char))
  char)

(defmethod stream-write-sequence
    ((stream ssl-stream) (thing string) &optional start end)
  (let ((bytes (map '(simple-array (unsigned-byte 8) (*)) #'char-code thing)))
    (stream-write-sequence stream bytes start end)))

(defmethod stream-line-column ((stream ssl-stream))
  nil)

(defmethod stream-listen ((stream ssl-stream))
  (warn "stream-listen")
  (call-next-method))

(defmethod stream-read-char-no-hang ((stream ssl-stream))
  (warn "stream-read-char-no-hang")
  (call-next-method))

(defmethod stream-peek-char ((stream ssl-stream))
  (warn "stream-peek-char")
  (call-next-method))


;;; interface functions
;;;
(defun make-ssl-client-stream (socket &key (method 'ssl-v23-method))
  "Returns an SSL stream for the client socket descriptor SOCKET."
  (ensure-initialized method)
  (let ((stream (make-instance 'ssl-stream :socket socket))
        (handle (ssl-new *ssl-global-context*)))
    (setf (ssl-stream-handle stream) handle)
    ;; (let ((bio (bio-new-socket socket 0))) (ssl-set-bio handle bio bio))
    (ssl-set-bio handle (bio-new-lisp) (bio-new-lisp))
    (ssl-set-connect-state handle)
    (ensure-ssl-funcall socket handle #'ssl-connect 0.25 handle)
    stream))

(defun make-ssl-server-stream
    (socket &key certificate key (method 'ssl-v23-method))
  "Returns an SSL stream for the server socket descriptor SOCKET.
CERTIFICATE is the path to a file containing the PEM-encoded certificate for
 your server. KEY is the path to the PEM-encoded key for the server, which
must not be associated with a passphrase."
  (ensure-initialized method)
  (let ((stream (make-instance 'ssl-server-stream
		 :socket socket
		 :certificate certificate
		 :key key))
        (handle (ssl-new *ssl-global-context*))
	(bio (bio-new-lisp)))
    (setf (ssl-stream-handle stream) handle)
    (ssl-set-bio handle bio bio)
    (ssl-set-accept-state handle)
    (when (zerop (ssl-set-cipher-list handle "ALL"))
      (error 'ssl-error-initialize :reason "Can't set SSL cipher list"))
    (when key
      (unless (eql 1 (ssl-use-rsa-privatekey-file handle
						  key
						  +ssl-filetype-pem+))
        (error 'ssl-error-initialize :reason "Can't load RSA private key ~A")))
    (when certificate
      (unless (eql 1 (ssl-use-certificate-file handle
					       certificate
					       +ssl-filetype-pem+))
        (error 'ssl-error-initialize
	       :reason "Can't load certificate ~A" certificate)))
    (ensure-ssl-funcall socket handle #'ssl-accept 0.25 handle)
    stream))
