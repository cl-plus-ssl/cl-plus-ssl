;;; Copyright (C) 2001, 2003  Eric Marsden
;;; Copyright (C) 2005  David Lichteblau
;;; "the conditions and ENSURE-SSL-FUNCALL are by Jochen Schmidt."
;;;
;;; See LICENSE for details.

(eval-when (:compile-toplevel)
  (declaim
   (optimize (speed 3) (space 1) (safety 1) (debug 0) (compilation-speed 0))))

(in-package :cl+ssl)

;;; Global state
;;;
(defvar *ssl-global-context* nil)
(defvar *ssl-global-method* nil)
(defvar *bio-lisp-method* nil)

(defparameter *blockp* t)
(defparameter *partial-read-p* nil)

(defun ssl-initialized-p ()
  (and *ssl-global-context* *ssl-global-method*))


;;; Constants
;;;
(defconstant +ssl-filetype-pem+ 1)
(defconstant +ssl-filetype-asn1+ 2)
(defconstant +ssl-filetype-default+ 3)

(defconstant +SSL_CTRL_SET_SESS_CACHE_MODE+ 44)
(defconstant +SSL_CTRL_MODE+ 33)

(defconstant +SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER+ 2)

;;; Misc
;;;
(defmacro while (cond &body body)
  `(do () ((not ,cond)) ,@body))


;;; Function definitions
;;;
(declaim (inline ssl-write ssl-read ssl-connect ssl-accept))

(cffi:defctype ssl-method :pointer)
(cffi:defctype ssl-ctx :pointer)
(cffi:defctype ssl-pointer :pointer)

(cffi:defcfun ("SSL_get_version" ssl-get-version)
    :string
  (ssl ssl-pointer))
(cffi:defcfun ("SSL_load_error_strings" ssl-load-error-strings)
    :void)
(cffi:defcfun ("SSL_library_init" ssl-library-init)
    :int)
(cffi:defcfun ("SSLv2_client_method" ssl-v2-client-method)
    ssl-method)
(cffi:defcfun ("SSLv23_client_method" ssl-v23-client-method)
    ssl-method)
(cffi:defcfun ("SSLv23_server_method" ssl-v23-server-method)
    ssl-method)
(cffi:defcfun ("SSLv23_method" ssl-v23-method)
    ssl-method)
(cffi:defcfun ("SSLv3_client_method" ssl-v3-client-method)
    ssl-method)
(cffi:defcfun ("SSLv3_server_method" ssl-v3-server-method)
    ssl-method)
(cffi:defcfun ("SSLv3_method" ssl-v3-method)
    ssl-method)
(cffi:defcfun ("TLSv1_client_method" ssl-TLSv1-client-method)
    ssl-method)
(cffi:defcfun ("TLSv1_server_method" ssl-TLSv1-server-method)
    ssl-method)
(cffi:defcfun ("TLSv1_method" ssl-TLSv1-method)
    ssl-method)

(cffi:defcfun ("SSL_CTX_new" ssl-ctx-new)
    ssl-ctx
  (method ssl-method))
(cffi:defcfun ("SSL_new" ssl-new)
    ssl-pointer
  (ctx ssl-ctx))
(cffi:defcfun ("SSL_get_fd" ssl-get-fd)
    :int
  (ssl ssl-pointer))
(cffi:defcfun ("SSL_set_fd" ssl-set-fd)
    :int
  (ssl ssl-pointer)
  (fd :int))
(cffi:defcfun ("SSL_set_bio" ssl-set-bio)
    :void
  (ssl ssl-pointer)
  (rbio :pointer)
  (wbio :pointer))
(cffi:defcfun ("SSL_get_error" ssl-get-error)
    :int
  (ssl ssl-pointer)
  (ret :int))
(cffi:defcfun ("SSL_set_connect_state" ssl-set-connect-state)
    :void
  (ssl ssl-pointer))
(cffi:defcfun ("SSL_set_accept_state" ssl-set-accept-state)
    :void
  (ssl ssl-pointer))
(cffi:defcfun ("SSL_connect" ssl-connect)
    :int
  (ssl ssl-pointer))
(cffi:defcfun ("SSL_accept" ssl-accept)
    :int
  (ssl ssl-pointer))
(cffi:defcfun ("SSL_write" ssl-write)
    :int
  (ssl ssl-pointer)
  (buf :pointer)
  (num :int))
(cffi:defcfun ("SSL_read" ssl-read)
    :int
  (ssl ssl-pointer)
  (buf :pointer)
  (num :int))
(cffi:defcfun ("SSL_shutdown" ssh-shutdown)
    :void
  (ssl ssl-pointer))
(cffi:defcfun ("SSL_free" ssl-free)
    :void
  (ssl ssl-pointer))
(cffi:defcfun ("SSL_CTX_free" ssl-ctx-free)
    :void
  (ctx ssl-ctx))
(cffi:defcfun ("RAND_seed" rand-seed)
    :void
  (buf :pointer)
  (num :int))
(cffi:defcfun ("BIO_ctrl" bio-set-fd)
    :long
  (bio :pointer)
  (cmd :int)
  (larg :long)
  (parg :pointer))
(cffi:defcfun ("BIO_new_socket" bio-new-socket)
    :pointer
  (fd :int)
  (close-flag :int))
(cffi:defcfun ("BIO_new" bio-new)
    :pointer
  (method :pointer))

(cffi:defcfun ("ERR_get_error" err-get-error)
    :unsigned-long)
(cffi:defcfun ("ERR_error_string" err-error-string)
    :string
  (e :unsigned-long)
  (buf :pointer))

(cffi:defcfun ("SSL_set_cipher_list" ssl-set-cipher-list)
    :int
  (ssl ssl-pointer)
  (str :string))
(cffi:defcfun ("SSL_use_RSAPrivateKey_file" ssl-use-rsa-privatekey-file)
    :int
  (ssl ssl-pointer)
  (str :string)
  ;; either +ssl-filetype-pem+ or +ssl-filetype-asn1+
  (type :int))
(cffi:defcfun
    ("SSL_CTX_use_RSAPrivateKey_file" ssl-ctx-use-rsa-privatekey-file)
    :int
  (ctx ssl-ctx)
  (type :int))
(cffi:defcfun ("SSL_use_certificate_file" ssl-use-certificate-file)
    :int
  (ssl ssl-pointer)
  (str :string)
  (type :int))
(cffi:defcfun ("SSL_CTX_use_certificate_chain_file" ssl-ctx-use-certificate-chain-file)
    :int
  (ctx ssl-ctx)
  (str :string))
(cffi:defcfun ("SSL_CTX_load_verify_locations" ssl-ctx-load-verify-locations)
    :int
  (ctx ssl-ctx)
  (CAfile :string)
  (CApath :string))
(cffi:defcfun ("SSL_CTX_set_client_CA_list" ssl-ctx-set-client-ca-list)
    :void
  (ctx ssl-ctx)
  (list ssl-pointer))
(cffi:defcfun ("SSL_load_client_CA_file" ssl-load-client-ca-file)
    ssl-pointer
  (file :string))

(cffi:defcfun ("SSL_CTX_ctrl" ssl-ctx-ctrl)
    :long
  (ctx ssl-ctx)
  (cmd :int)
  (larg :long)
  (parg :long))

(cffi:defcfun ("SSL_CTX_set_default_passwd_cb" ssl-ctx-set-default-passwd-cb)
    :void
  (ctx ssl-ctx)
  (pem_passwd_cb :pointer))

;;; Funcall wrapper
;;;
(defvar *socket*)

(declaim (inline ensure-ssl-funcall))
(defun ensure-ssl-funcall (stream handle func &rest args)
  (loop
     (let ((nbytes
	    (let ((*socket* stream))	;for Lisp-BIO callbacks
	      (apply func args))))
       (when (plusp nbytes)
	 (return nbytes))
       (let ((error (ssl-get-error handle nbytes)))
	 (case error
	   (#.+ssl-error-want-read+
	    (input-wait stream
			(ssl-get-fd handle)
			(ssl-stream-deadline stream)))
	   (#.+ssl-error-want-write+
	    (output-wait stream
			 (ssl-get-fd handle)
			 (ssl-stream-deadline stream)))
	   (t
	    (ssl-signal-error handle func error nbytes)))))))


;;; Waiting for output to be possible

#+clozure-common-lisp
(defun milliseconds-until-deadline (deadline stream)
  (let* ((now (get-internal-real-time)))
    (if (> now deadline)
	(error 'ccl::communication-deadline-expired :stream stream)
	(values
	 (round (- deadline now) (/ internal-time-units-per-second 1000))))))

#+clozure-common-lisp
(defun output-wait (stream fd deadline)
  (unless deadline
    (setf deadline (stream-deadline (ssl-stream-socket stream))))
  (let* ((timeout
	  (if deadline
	      (milliseconds-until-deadline deadline stream)
	      nil)))
    (multiple-value-bind (win timedout error)
	(ccl::process-output-wait fd timeout)
      (unless win
	(if timedout
	    (error 'ccl::communication-deadline-expired :stream stream)
	    (ccl::stream-io-error stream (- error) "write"))))))

#+sbcl
(defun output-wait (stream fd deadline)
  (declare (ignore stream))
  (let ((timeout
	 ;; *deadline* is handled by wait-until-fd-usable automatically,
	 ;; but we need to turn a user-specified deadline into a timeout
	 (when deadline
	   (/ (- deadline (get-internal-real-time))
	      internal-time-units-per-second))))
    (sb-sys:wait-until-fd-usable fd :output timeout)))

#-(or clozure-common-lisp sbcl)
(defun output-wait (stream fd deadline)
  (declare (ignore stream fd deadline))
  ;; This situation means that the lisp set our fd to non-blocking mode,
  ;; and streams.lisp didn't know how to undo that.
  (warn "non-blocking stream encountered unexpectedly"))


;;; Waiting for input to be possible

#+clozure-common-lisp
(defun input-wait (stream fd deadline)
  (unless deadline
    (setf deadline (stream-deadline (ssl-stream-socket stream))))
  (let* ((timeout
	  (if deadline
	      (milliseconds-until-deadline deadline stream)
	      nil)))
    (multiple-value-bind (win timedout error)
	(ccl::process-input-wait fd timeout)
      (unless win
	(if timedout
	    (error 'ccl::communication-deadline-expired :stream stream)
	    (ccl::stream-io-error stream (- error) "read"))))))

#+sbcl
(defun input-wait (stream fd deadline)
  (declare (ignore stream))
  (let ((timeout
	 ;; *deadline* is handled by wait-until-fd-usable automatically,
	 ;; but we need to turn a user-specified deadline into a timeout
	 (when deadline
	   (/ (- deadline (get-internal-real-time))
	      internal-time-units-per-second))))
    (sb-sys:wait-until-fd-usable fd :input timeout)))

#-(or clozure-common-lisp sbcl)
(defun input-wait (stream fd deadline)
  (declare (ignore stream fd deadline))
  ;; This situation means that the lisp set our fd to non-blocking mode,
  ;; and streams.lisp didn't know how to undo that.
  (warn "non-blocking stream encountered unexpectedly"))


;;; Encrypted PEM files support
;;;

;; based on http://www.openssl.org/docs/ssl/SSL_CTX_set_default_passwd_cb.html

(defvar *pem-password* ""
  "The callback registered with SSL_CTX_set_default_passwd_cb
will use this value.")

;; The callback itself
(cffi:defcallback pem-password-callback :int
    ((buf :pointer) (size :int) (rwflag :int) (unused :pointer))
  (let* ((password-str (coerce *pem-password* 'base-string))
         (tmp (cffi:foreign-string-alloc password-str)))
    (cffi:foreign-funcall "strncpy"
                          :pointer buf
                          :pointer tmp
                          :int size)
    (cffi:foreign-string-free tmp)
    (setf (cffi:mem-ref buf :char (1- size)) 0)
    (cffi:foreign-funcall "strlen" :pointer buf :int)))

;; The macro to be used by other code to provide password
;; when loading PEM file.
(defmacro with-pem-password ((password) &body body)
  `(let ((*pem-password* (or ,password "")))
         ,@body))


;;; Initialization
;;;

(defun init-prng (seed-byte-sequence)
  (let* ((length (length seed-byte-sequence))
         (buf (cffi-sys::make-shareable-byte-vector length)))
    (dotimes (i length)
      (setf (elt buf i) (elt seed-byte-sequence i)))
    (cffi-sys::with-pointer-to-vector-data (ptr buf)
      (rand-seed ptr length))))

(defun ssl-ctx-set-session-cache-mode (ctx mode)
  (ssl-ctx-ctrl ctx +SSL_CTRL_SET_SESS_CACHE_MODE+ mode 0))

(defun initialize (&key (method 'ssl-v23-method) rand-seed)
  (setf *bio-lisp-method* (make-bio-lisp-method))
  (ssl-load-error-strings)
  (ssl-library-init)
  (when rand-seed
    (init-prng rand-seed))
  (setf *ssl-global-method* (funcall method))
  (setf *ssl-global-context* (ssl-ctx-new *ssl-global-method*))
  (ssl-ctx-set-session-cache-mode *ssl-global-context* 3)
  (ssl-ctx-set-default-passwd-cb *ssl-global-context* 
                                 (cffi:callback pem-password-callback)))

(defun ensure-initialized (&key (method 'ssl-v23-method) (rand-seed nil))
  "In most cases you do *not* need to call this function, because it 
is called automatically by all other functions. The only reason to 
call it explicitly is to supply the RAND-SEED parameter. In this case
do it before calling any other functions.

Just leave the default value for the METHOD parameter.

RAND-SEED is an octet sequence to initialize OpenSSL random number generator. 
On many platforms, including Linux and Windows, it may be leaved NIL (default), 
because OpenSSL initializes the random number generator from OS specific service. 
But for example on Solaris it may be necessary to supply this value.
The minimum length required by OpenSSL is 128 bits.
See ttp://www.openssl.org/support/faq.html#USER1 for details.

Hint: do not use Common Lisp RANDOM function to generate the RAND-SEED, 
because the function usually returns predictable values."
  (unless (ssl-initialized-p)
    (initialize :method method :rand-seed rand-seed))
  (unless *bio-lisp-method*
    (setf *bio-lisp-method* (make-bio-lisp-method))))

(defun use-certificate-chain-file (certificate-chain-file)
  "Loads a PEM encoded certificate chain file CERTIFICATE-CHAIN-FILE
and adds the chain to global context. The certificates must be sorted 
starting with the subject's certificate (actual client or server certificate),
followed by intermediate CA certificates if applicable, and ending at 
the highest level (root) CA. Note: the RELOAD function clears the global 
context and in particular the loaded certificate chain."
  (ensure-initialized)
  (ssl-ctx-use-certificate-chain-file *ssl-global-context* certificate-chain-file))

(defun reload ()
  (cffi:load-foreign-library 'libssl)
  (cffi:load-foreign-library 'libeay32)
  (setf *ssl-global-context* nil)
  (setf *ssl-global-method* nil))
