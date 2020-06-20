;;;; -*- Mode: LISP; Syntax: COMMON-LISP; indent-tabs-mode: nil; coding: utf-8; show-trailing-whitespace: t -*-
;;;
;;; Copyright (C) 2001, 2003  Eric Marsden
;;; Copyright (C) 2005  David Lichteblau
;;; "the conditions and ENSURE-SSL-FUNCALL are by Jochen Schmidt."
;;;
;;; See LICENSE for details.

#+xcvb (module (:depends-on ("package" "conditions")))

(eval-when (:compile-toplevel)
  (declaim
   (optimize (speed 3) (space 1) (safety 1) (debug 0) (compilation-speed 0))))

(in-package :cl+ssl)

;;; Some lisps (CMUCL) fail when we try to define
;;; a foreign function which is absent in the loaded
;;; foreign library. CMUCL fails when the compiled .fasl
;;; file is loaded, and the failure can not be
;;; captured even by CL condition handlers, i.e.
;;; wrapping (defcfun "removed-function" ...)
;;; into (ignore-errors ...) doesn't help.
;;;
;;; See https://gitlab.common-lisp.net/cmucl/cmucl/issues/74
;;;
;;; As OpenSSL often changs API (removes / adds functions)
;;; we need to solve this problem for CMUCL.
;;;
;;; We do this on CMUCL by calling functions which exists
;;; not in all OpenSSL versions through a pointer
;;; received with cffi:foreign-symbol-pointer.
;;; So a lisp wrapper function for such foreign function
;;; looks up a pointer to the required foreign function
;;; in a hash table.

(defparameter *late-bound-foreign-function-pointers*
  (make-hash-table :test 'equal))

(defmacro defcfun-late-bound (name-and-options &body body)
  (assert (not (eq (alexandria:lastcar body)
                   '&rest))
          (body)
          "The BODY format is implemented in a limited way
comparing to CFFI:DEFCFUN - we don't support the &REST which specifies vararg
functions. Feel free to implement the support if you have a use case.")
  (assert (and (>= (length name-and-options) 2)
               (stringp (first name-and-options))
               (symbolp (second name-and-options)))
          (name-and-options)
          "Unsupported NAME-AND-OPTIONS format: ~S.
\(Of all the NAME-AND-OPTIONS variants allowed by CFFI:DEFCFUN we have only
implemented support for (FOREIGN-NAME LISP-NAME ...) where FOREIGN-NAME is a
STRING and LISP-NAME is a SYMBOL. Fell free to implement support the remaining
variants if you have use cases for them.)"
          name-and-options)

  (let ((foreign-name-str (first name-and-options))
        (lisp-name (second name-and-options))
        (docstring (when (stringp (car body)) (pop body)))
        (return-type (first body))
        (arg-names (mapcar #'first (rest body)))
        (arg-types (mapcar #'second (rest body)))
        (library (getf (cddr name-and-options) :library))
        (convention (getf (cddr name-and-options) :convention))
        (ptr-var (gensym (string 'ptr))))
    `(progn
       (setf (gethash ,foreign-name-str *late-bound-foreign-function-pointers*)
             (or (cffi:foreign-symbol-pointer ,foreign-name-str
                                              ,@(when library `(:library ',library)))
                 'foreign-symbol-not-found))
       (defun ,lisp-name (,@arg-names)
         ,@(when docstring (list docstring))
         (let ((,ptr-var (gethash ,foreign-name-str *late-bound-foreign-function-pointers*)))
           (when (null ,ptr-var)
             (error "Unexpacted state, no value in *late-bound-foreign-function-pointers* for ~A"
                    ,foreign-name-str))
           (when (eq ,ptr-var 'foreign-symbol-not-found)
             (error "The current version of OpenSSL libcrypto doesn't provide ~A"
                    ,foreign-name-str))
           (cffi:foreign-funcall-pointer ,ptr-var
                                         ,(when convention (list convention))
                                         ,@(mapcan #'list arg-types arg-names)
                                         ,return-type))))))

(defmacro defcfun-versioned ((&key since vanished) name-and-options &body body)
  (if (and (or since vanished)
           (member :cmucl *features*))
      `(defcfun-late-bound ,name-and-options ,@body)
      `(cffi:defcfun ,name-and-options ,@body)))


;;; Code for checking that we got the correct foreign symbols right.
;;; Implemented only for LispWorks for now.
(defvar *cl+ssl-ssl-foreign-function-names* nil)
(defvar *cl+ssl-crypto-foreign-function-names* nil)

#+lispworks
(defun check-cl+ssl-symbols ()
  (dolist (ssl-symbol *cl+ssl-ssl-foreign-function-names*)
    (when (fli:null-pointer-p (fli:make-pointer :symbol-name ssl-symbol :module 'libssl :errorp nil))
      (format *error-output* "Symbol ~s undefined~%" ssl-symbol)))
  (dolist (crypto-symbol *cl+ssl-crypto-foreign-function-names*)
    (when (fli:null-pointer-p (fli:make-pointer :symbol-name crypto-symbol :module 'libcrypto :errorp nil))
      (format *error-output* "Symbol ~s undefined~%" crypto-symbol))))

(defmacro define-ssl-function-ex ((&key since vanished) name-and-options &body body)
  `(progn
     ;; debugging
     (pushnew  ,(car name-and-options)
               *cl+ssl-ssl-foreign-function-names*
               :test 'equal)
     (defcfun-versioned (:since ,since :vanished ,vanished)
         ,(append name-and-options '(:library libssl))
       ,@body)))

(defmacro define-ssl-function (name-and-options &body body)
  `(define-ssl-function-ex () ,name-and-options ,@body))

(defmacro define-crypto-function-ex ((&key since vanished) name-and-options &body body)
  `(progn
     ;; debugging
     (pushnew ,(car name-and-options)
              *cl+ssl-crypto-foreign-function-names*
              :test 'equal)
     (defcfun-versioned (:since ,since :vanished ,vanished)
         ;; On Darwin, LispWorks has boringssl always loaded
         ;; (https://github.com/cl-plus-ssl/cl-plus-ssl/issues/61),
         ;; ABCL somehow has libressl loaded
         ;; (https://github.com/cl-plus-ssl/cl-plus-ssl/pull/89),
         ;; and when we load openssl and declare ffi functions
         ;; without explicitly specifying the :library option,
         ;; some foreign symbols are resolved as boringssl / libressl symbols,
         ;; others are resolved as openssl functions.
         ;; This mix results in failures, of course.
         ;; We fix these two implementations by passing the :library option.
         ;; Not for other implementations because this may be
         ;; incompatible with :cl+ssl-foreign-libs-already-loaded
         ;; but these two implementations just break without
         ;; that, so it's better to possibly sacrify the
         ;; :cl+ssl-foreign-libs-already-loaded (we haven't tested)
         ;; than have them broken completely.
         ;; TODO: extend the :cl+ssl-foreign-libs-already-loaded
         ;; mechanism with possibility for user to specify value
         ;; for the :library option.
         ,(append name-and-options
                  #+(and (or abcl lispworks) darwin) '(:library libcrypto))
       ,@body)))

(defmacro define-crypto-function (name-and-options &body body)
  `(define-crypto-function-ex () ,name-and-options ,@body))


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

(defconstant +SSL-CTRL-OPTIONS+ 32)
(defconstant +SSL_CTRL_SET_SESS_CACHE_MODE+ 44)
(defconstant +SSL_CTRL_MODE+ 33)

(defconstant +SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER+ 2)

(defconstant +RSA_F4+ #x10001)

(defconstant +SSL-SESS-CACHE-OFF+ #x0000
  "No session caching for client or server takes place.")
(defconstant +SSL-SESS-CACHE-CLIENT+ #x0001
  "Client sessions are added to the session cache.
As there is no reliable way for the OpenSSL library to know whether a session should be reused
or which session to choose (due to the abstract BIO layer the SSL engine does not have details
about the connection), the application must select the session to be reused by using the
SSL-SET-SESSION function. This option is not activated by default.")
(defconstant +SSL-SESS-CACHE-SERVER+ #x0002
  "Server sessions are added to the session cache.
When a client proposes a session to be reused, the server looks for the corresponding session
in (first) the internal session cache (unless +SSL-SESS-CACHE-NO-INTERNAL-LOOKUP+ is set), then
(second) in the external cache if available. If the session is found, the server will try to
reuse the session. This is the default.")
(defconstant +SSL-SESS-CACHE-BOTH+ (logior +SSL-SESS-CACHE-CLIENT+ +SSL-SESS-CACHE-SERVER+)
  "Enable both +SSL-SESS-CACHE-CLIENT+ and +SSL-SESS-CACHE-SERVER+ at the same time.")
(defconstant +SSL-SESS-CACHE-NO-AUTO-CLEAR+ #x0080
  "Normally the session cache is checked for expired sessions every 255 connections using the
SSL-CTX-FLUSH-SESSIONS function. Since this may lead to a delay which cannot be controlled,
the automatic flushing may be disabled and SSL-CTX-FLUSH-SESSIONS can be called explicitly
by the application.")
(defconstant +SSL-SESS-CACHE-NO-INTERNAL-LOOKUP+ #x0100
  "By setting this flag, session-resume operations in an SSL/TLS server will not automatically
look up sessions in the internal cache, even if sessions are automatically stored there.
If external session caching callbacks are in use, this flag guarantees that all lookups are
directed to the external cache. As automatic lookup only applies for SSL/TLS servers, the flag
has no effect on clients.")
(defconstant +SSL-SESS-CACHE-NO-INTERNAL-STORE+ #x0200
  "Depending on the presence of +SSL-SESS-CACHE-CLIENT+ and/or +SSL-SESS-CACHE-SERVER+, sessions
negotiated in an SSL/TLS handshake may be cached for possible reuse. Normally a new session is
added to the internal cache as well as any external session caching (callback) that is configured
for the SSL-CTX. This flag will prevent sessions being stored in the internal cache (though the
application can add them manually using SSL-CTX-ADD-SESSION). Note: in any SSL/TLS servers where
external caching is configured, any successful session lookups in the external cache (ie. for
session-resume requests) would normally be copied into the local cache before processing continues
- this flag prevents these additions to the internal cache as well.")
(defconstant +SSL-SESS-CACHE-NO-INTERNAL+ (logior +SSL-SESS-CACHE-NO-INTERNAL-LOOKUP+ +SSL-SESS-CACHE-NO-INTERNAL-STORE+)
  "Enable both +SSL-SESS-CACHE-NO-INTERNAL-LOOKUP+ and +SSL-SESS-CACHE-NO-INTERNAL-STORE+ at the same time.")

(defconstant +SSL-VERIFY-NONE+ #x00)
(defconstant +SSL-VERIFY-PEER+ #x01)
(defconstant +SSL-VERIFY-FAIL-IF-NO-PEER-CERT+ #x02)
(defconstant +SSL-VERIFY-CLIENT-ONCE+ #x04)

(defconstant +SSL-OP-ALL+ #x80000BFF)

(defconstant +SSL-OP-NO-SSLv2+   #x01000000)
(defconstant +SSL-OP-NO-SSLv3+   #x02000000)
(defconstant +SSL-OP-NO-TLSv1+   #x04000000)
(defconstant +SSL-OP-NO-TLSv1-2+ #x08000000)
(defconstant +SSL-OP-NO-TLSv1-1+ #x10000000)

(defvar *tmp-rsa-key-512* nil)
(defvar *tmp-rsa-key-1024* nil)
(defvar *tmp-rsa-key-2048* nil)

;;; Misc
;;;
(defmacro while (cond &body body)
  `(do () ((not ,cond)) ,@body))


;;; Function definitions
;;;

(cffi:defcfun (#-windows "close" #+windows "closesocket" close-socket)
    :int
  (socket :int))

(declaim (inline ssl-write ssl-read ssl-connect ssl-accept))

(cffi:defctype ssl-method :pointer)
(cffi:defctype ssl-ctx :pointer)
(cffi:defctype ssl-pointer :pointer)


(define-crypto-function-ex (:vanished "1.1.0") ("SSLeay" ssl-eay)
        :long)

(define-crypto-function-ex (:since "1.1.0") ("OpenSSL_version_num" openssl-version-num)
        :long)

(defun compat-openssl-version ()
  (or (ignore-errors (openssl-version-num))
      (ignore-errors (ssl-eay))
      (error "No OpenSSL version number could be determined, both SSLeay and OpenSSL_version_num failed.")))

(defun encode-openssl-version (major minor &optional (patch 0) (prerelease))
  "Builds a version number to compare OpenSSL against.
Note: the _really_ old formats (<= 0.9.4) are not supported."
  (declare (type (integer 0 3) major)
           (type (integer 0 10) minor)
           (type (integer 0 20) patch))
  (logior (ash major 28)
          (ash minor 20)
          (ash patch 4)
          (if prerelease #xf #x0)))

(defun openssl-is-at-least (major minor &optional (patch 0) (prerelease))
  (>= (compat-openssl-version)
      (encode-openssl-version major minor patch prerelease)))

(defun openssl-is-not-even (major minor &optional (patch 0) (prerelease))
  (< (compat-openssl-version)
     (encode-openssl-version major minor patch prerelease)))

(defun libresslp ()
  ;; LibreSSL can be distinguished by
  ;; OpenSSL_version_num() always returning 0x020000000,
  ;; where 2 is the major version number.
  ;; http://man.openbsd.org/OPENSSL_VERSION_NUMBER.3
  ;; And OpenSSL will never use the major version 2:
  ;; "This document outlines the design of OpenSSL 3.0, the next version of OpenSSL after 1.1.1"
  ;; https://www.openssl.org/docs/OpenSSL300Design.html
  (= #x20000000 (compat-openssl-version)))

(define-ssl-function ("SSL_get_version" ssl-get-version)
    :string
  (ssl ssl-pointer))
(define-ssl-function-ex (:vanished "1.1.0") ("SSL_load_error_strings" ssl-load-error-strings)
    :void)
(define-ssl-function-ex (:vanished "1.1.0") ("SSL_library_init" ssl-library-init)
    :int)
;;
;; We don't refer SSLv2_client_method as the default
;; builds of OpenSSL do not have it, due to insecurity
;; of the SSL v2 protocol (see https://www.openssl.org/docs/ssl/SSL_CTX_new.html
;; and https://github.com/cl-plus-ssl/cl-plus-ssl/issues/6)
;;
;; (define-ssl-function ("SSLv2_client_method" ssl-v2-client-method)
;;     ssl-method)
(define-ssl-function-ex (:vanished "1.1.0") ("SSLv23_client_method" ssl-v23-client-method)
    ssl-method)
(define-ssl-function-ex (:vanished "1.1.0") ("SSLv23_server_method" ssl-v23-server-method)
    ssl-method)
(define-ssl-function-ex (:vanished "1.1.0") ("SSLv23_method" ssl-v23-method)
    ssl-method)
(define-ssl-function-ex (:vanished "1.1.0") ("SSLv3_client_method" ssl-v3-client-method)
    ssl-method)
(define-ssl-function-ex (:vanished "1.1.0") ("SSLv3_server_method" ssl-v3-server-method)
    ssl-method)
(define-ssl-function-ex (:vanished "1.1.0") ("SSLv3_method" ssl-v3-method)
    ssl-method)
(define-ssl-function ("TLSv1_client_method" ssl-TLSv1-client-method)
    ssl-method)
(define-ssl-function ("TLSv1_server_method" ssl-TLSv1-server-method)
    ssl-method)
(define-ssl-function ("TLSv1_method" ssl-TLSv1-method)
    ssl-method)
(define-ssl-function-ex (:since "1.0.2") ("TLSv1_1_client_method" ssl-TLSv1-1-client-method)
    ssl-method)
(define-ssl-function-ex (:since "1.0.2") ("TLSv1_1_server_method" ssl-TLSv1-1-server-method)
    ssl-method)
(define-ssl-function-ex (:since "1.0.2") ("TLSv1_1_method" ssl-TLSv1-1-method)
    ssl-method)
(define-ssl-function-ex (:since "1.0.2") ("TLSv1_2_client_method" ssl-TLSv1-2-client-method)
    ssl-method)
(define-ssl-function-ex (:since "1.0.2") ("TLSv1_2_server_method" ssl-TLSv1-2-server-method)
    ssl-method)
(define-ssl-function-ex (:since "1.0.2") ("TLSv1_2_method" ssl-TLSv1-2-method)
    ssl-method)
(define-ssl-function-ex (:since "1.1.0") ("TLS_method" tls-method)
    ssl-method)

(define-ssl-function ("SSL_CTX_new" ssl-ctx-new)
    ssl-ctx
  (method ssl-method))
(define-ssl-function ("SSL_new" ssl-new)
    ssl-pointer
  (ctx ssl-ctx))
(define-ssl-function ("SSL_get_fd" ssl-get-fd)
    :int
  (ssl ssl-pointer))
(define-ssl-function ("SSL_set_fd" ssl-set-fd)
    :int
  (ssl ssl-pointer)
  (fd :int))
(define-ssl-function ("SSL_set_bio" ssl-set-bio)
    :void
  (ssl ssl-pointer)
  (rbio :pointer)
  (wbio :pointer))
(define-ssl-function ("SSL_get_error" ssl-get-error)
    :int
  (ssl ssl-pointer)
  (ret :int))
(define-ssl-function ("SSL_set_connect_state" ssl-set-connect-state)
    :void
  (ssl ssl-pointer))
(define-ssl-function ("SSL_set_accept_state" ssl-set-accept-state)
    :void
  (ssl ssl-pointer))
(define-ssl-function ("SSL_connect" ssl-connect)
    :int
  (ssl ssl-pointer))
(define-ssl-function ("SSL_accept" ssl-accept)
    :int
  (ssl ssl-pointer))
(define-ssl-function ("SSL_write" ssl-write)
    :int
  (ssl ssl-pointer)
  (buf :pointer)
  (num :int))
(define-ssl-function ("SSL_read" ssl-read)
    :int
  (ssl ssl-pointer)
  (buf :pointer)
  (num :int))
(define-ssl-function ("SSL_shutdown" ssl-shutdown)
    :void
  (ssl ssl-pointer))
(define-ssl-function ("SSL_free" ssl-free)
    :void
  (ssl ssl-pointer))
(define-ssl-function ("SSL_CTX_free" ssl-ctx-free)
    :void
  (ctx ssl-ctx))
(define-crypto-function ("BIO_ctrl" bio-set-fd)
    :long
  (bio :pointer)
  (cmd :int)
  (larg :long)
  (parg :pointer))
(define-crypto-function ("BIO_new_socket" bio-new-socket)
    :pointer
  (fd :int)
  (close-flag :int))
(define-crypto-function ("BIO_new" bio-new)
    :pointer
  (method :pointer))

(define-crypto-function ("ERR_get_error" err-get-error)
    :unsigned-long)
(define-crypto-function ("ERR_error_string" err-error-string)
    :string
  (e :unsigned-long)
  (buf :pointer))

(define-ssl-function ("SSL_set_cipher_list" ssl-set-cipher-list)
    :int
  (ssl ssl-pointer)
  (str :string))
(define-ssl-function ("SSL_use_RSAPrivateKey_file" ssl-use-rsa-privatekey-file)
    :int
  (ssl ssl-pointer)
  (str :string)
  ;; either +ssl-filetype-pem+ or +ssl-filetype-asn1+
  (type :int))
(define-ssl-function
    ("SSL_CTX_use_RSAPrivateKey_file" ssl-ctx-use-rsa-privatekey-file)
    :int
  (ctx ssl-ctx)
  (type :int))
(define-ssl-function ("SSL_use_PrivateKey_file" ssl-use-privatekey-file)
  :int
  (ssl ssl-pointer)
  (str :string)
  ;; either +ssl-filetype-pem+ or +ssl-filetype-asn1+
  (type :int))
(define-ssl-function
    ("SSL_CTX_use_PrivateKey_file" ssl-ctx-use-privatekey-file)
  :int
  (ctx ssl-ctx)
  (type :int))
(define-ssl-function ("SSL_use_certificate_file" ssl-use-certificate-file)
    :int
  (ssl ssl-pointer)
  (str :string)
  (type :int))
#+new-openssl
(define-ssl-function ("SSL_CTX_set_options" ssl-ctx-set-options)
                 :long
               (ctx :pointer)
               (options :long))
#-new-openssl
(defun ssl-ctx-set-options (ctx options)
  (ssl-ctx-ctrl ctx +SSL-CTRL-OPTIONS+ options (cffi:null-pointer)))
(define-ssl-function ("SSL_CTX_set_cipher_list" ssl-ctx-set-cipher-list%)
    :int
  (ctx :pointer)
  (ciphers :pointer))
(defun ssl-ctx-set-cipher-list (ctx ciphers)
  (cffi:with-foreign-string (ciphers* ciphers)
    (when (= 0 (ssl-ctx-set-cipher-list% ctx ciphers*))
      (error 'ssl-error-initialize :reason "Can't set SSL cipher list" :queue (read-ssl-error-queue)))))
(define-ssl-function ("SSL_CTX_use_certificate_chain_file" ssl-ctx-use-certificate-chain-file)
    :int
  (ctx ssl-ctx)
  (str :string))
(define-ssl-function ("SSL_CTX_load_verify_locations" ssl-ctx-load-verify-locations)
    :int
  (ctx ssl-ctx)
  (CAfile :string)
  (CApath :string))
(define-ssl-function ("SSL_CTX_set_client_CA_list" ssl-ctx-set-client-ca-list)
    :void
  (ctx ssl-ctx)
  (list ssl-pointer))
(define-ssl-function ("SSL_load_client_CA_file" ssl-load-client-ca-file)
    ssl-pointer
  (file :string))

(define-ssl-function ("SSL_CTX_ctrl" ssl-ctx-ctrl)
    :long
  (ctx ssl-ctx)
  (cmd :int)
  ;; Despite declared as long in the original OpenSSL headers,
  ;; passing to larg for example 2181041151 which is the result of
  ;;     (logior cl+ssl::+SSL-OP-ALL+
  ;;             cl+ssl::+SSL-OP-NO-SSLv2+
  ;;             cl+ssl::+SSL-OP-NO-SSLv3+)
  ;; causes CFFI on 32 bit platforms to signal an error
  ;; "The value 2181041151 is not of the expected type (SIGNED-BYTE 32)"
  ;; The problem is that 2181041151 requires 32 bits by itself and
  ;; there is no place left for the sign bit.
  ;; In C the compiler silently coerces unsigned to signed,
  ;; but CFFI raises this error.
  ;; Therefore we use :UNSIGNED-LONG for LARG.
  (larg :unsigned-long)
  (parg :pointer))

(define-ssl-function ("SSL_ctrl" ssl-ctrl)
    :long
  (ssl :pointer)
  (cmd :int)
  (larg :long)
  (parg :pointer))

(define-ssl-function ("SSL_CTX_set_default_passwd_cb" ssl-ctx-set-default-passwd-cb)
    :void
  (ctx ssl-ctx)
  (pem_passwd_cb :pointer))

(define-crypto-function-ex (:vanished "1.1.0") ("CRYPTO_num_locks" crypto-num-locks) :int)
(define-crypto-function-ex (:vanished "1.1.0") ("CRYPTO_set_locking_callback" crypto-set-locking-callback)
    :void
  (fun :pointer))
(define-crypto-function-ex (:vanished "1.1.0") ("CRYPTO_set_id_callback" crypto-set-id-callback)
    :void
  (fun :pointer))

(define-crypto-function ("RAND_seed" rand-seed)
    :void
  (buf :pointer)
  (num :int))
(define-crypto-function ("RAND_bytes" rand-bytes)
    :int
  (buf :pointer)
  (num :int))

(define-ssl-function ("SSL_CTX_set_verify_depth" ssl-ctx-set-verify-depth)
    :void
  (ctx :pointer)
  (depth :int))

(define-ssl-function ("SSL_CTX_set_verify" ssl-ctx-set-verify)
    :void
  (ctx :pointer)
  (mode :int)
  (verify-callback :pointer))

(define-ssl-function ("SSL_get_verify_result" ssl-get-verify-result)
    :long
  (ssl ssl-pointer))

(define-ssl-function ("SSL_get_peer_certificate" ssl-get-peer-certificate)
    :pointer
  (ssl ssl-pointer))

;;; X509 & ASN1
(define-crypto-function ("X509_free" x509-free)
    :void
  (x509 :pointer))

(define-crypto-function ("X509_NAME_oneline" x509-name-oneline)
    :pointer
  (x509-name :pointer)
  (buf :pointer)
  (size :int))

(define-crypto-function ("X509_NAME_get_index_by_NID" x509-name-get-index-by-nid)
    :int
  (name :pointer)
  (nid :int)
  (lastpos :int))

(define-crypto-function ("X509_NAME_get_entry" x509-name-get-entry)
    :pointer
  (name :pointer)
  (log :int))

(define-crypto-function ("X509_NAME_ENTRY_get_data" x509-name-entry-get-data)
    :pointer
  (name-entry :pointer))

(define-crypto-function ("X509_get_issuer_name" x509-get-issuer-name)
    :pointer                            ; *X509_NAME
  (x509 :pointer))

(define-crypto-function ("X509_get_subject_name" x509-get-subject-name)
    :pointer                            ; *X509_NAME
  (x509 :pointer))

(define-crypto-function ("X509_get_ext_d2i" x509-get-ext-d2i)
    :pointer
  (cert :pointer)
  (nid :int)
  (crit :pointer)
  (idx :pointer))

(define-crypto-function ("X509_STORE_CTX_get_error" x509-store-ctx-get-error)
    :int
  (ctx :pointer))

(define-crypto-function ("d2i_X509" d2i-x509)
    :pointer
  (*px :pointer)
  (in :pointer)
  (len :int))

;; GENERAL-NAME types
(defconstant +GEN-OTHERNAME+  0)
(defconstant +GEN-EMAIL+  1)
(defconstant +GEN-DNS+    2)
(defconstant +GEN-X400+ 3)
(defconstant +GEN-DIRNAME+  4)
(defconstant +GEN-EDIPARTY+ 5)
(defconstant +GEN-URI+    6)
(defconstant +GEN-IPADD+  7)
(defconstant +GEN-RID+    8)

(defconstant +v-asn1-octet-string+ 4)
(defconstant +v-asn1-utf8string+ 12)
(defconstant +v-asn1-printablestring+ 19)
(defconstant +v-asn1-teletexstring+ 20)
(defconstant +v-asn1-iastring+ 22)
(defconstant +v-asn1-universalstring+ 28)
(defconstant +v-asn1-bmpstring+ 30)


(defconstant +NID-subject-alt-name+ 85)
(defconstant +NID-commonName+   13)

(cffi:defcstruct general-name
  (type :int)
  (data :pointer))

(define-crypto-function-ex (:vanished "1.1.0") ("sk_value" sk-value)
    :pointer
  (stack :pointer)
  (index :int))

(define-crypto-function-ex (:vanished "1.1.0") ("sk_num" sk-num)
    :int
  (stack :pointer))

(define-crypto-function-ex (:since "1.1.0") ("OPENSSL_sk_value" openssl-sk-value)
    :pointer
  (stack :pointer)
  (index :int))

(define-crypto-function-ex (:since "1.1.0") ("OPENSSL_sk_num" openssl-sk-num)
    :int
  (stack :pointer))

(declaim (ftype (function (cffi:foreign-pointer fixnum) cffi:foreign-pointer) sk-general-name-value))
(defun sk-general-name-value (names index)
  (if (and (not (libresslp))
           (openssl-is-at-least 1 1))
      (openssl-sk-value names index)
      (sk-value names index)))

(declaim (ftype (function (cffi:foreign-pointer) fixnum) sk-general-name-num))
(defun sk-general-name-num (names)
  (if (and (not (libresslp))
           (openssl-is-at-least 1 1))
      (openssl-sk-num names)
      (sk-num names)))

(define-crypto-function ("GENERAL_NAMES_free" general-names-free)
    :void
  (general-names :pointer))

(define-crypto-function ("ASN1_STRING_data" asn1-string-data)
    :pointer
  (asn1-string :pointer))

(define-crypto-function ("ASN1_STRING_length" asn1-string-length)
    :int
  (asn1-string :pointer))

(define-crypto-function ("ASN1_STRING_type" asn1-string-type)
    :int
  (asn1-string :pointer))

(cffi:defcstruct asn1_string_st
  (length :int)
  (type :int)
  (data :pointer)
  (flags :long))

;; X509 & ASN1 - end

(define-ssl-function ("SSL_CTX_set_default_verify_paths" ssl-ctx-set-default-verify-paths)
    :int
  (ctx :pointer))

(define-ssl-function-ex (:since "1.1.0") ("SSL_CTX_set_default_verify_dir" ssl-ctx-set-default-verify-dir)
    :int
  (ctx :pointer))

(define-ssl-function-ex (:since "1.1.0") ("SSL_CTX_set_default_verify_file" ssl-ctx-set-default-verify-file)
    :int
  (ctx :pointer))

(define-crypto-function ("RSA_generate_key" rsa-generate-key)
    :pointer
  (num :int)
  (e :unsigned-long)
  (callback :pointer)
  (opt :pointer))

(define-crypto-function ("RSA_free" rsa-free)
    :void
  (rsa :pointer))

(define-ssl-function-ex (:vanished "1.1.0") ("SSL_CTX_set_tmp_rsa_callback" ssl-ctx-set-tmp-rsa-callback)
    :pointer
  (ctx :pointer)
  (callback :pointer))

(cffi:defcallback tmp-rsa-callback :pointer ((ssl :pointer) (export-p :int) (key-length :int))
  (declare (ignore ssl export-p))
  (flet ((rsa-key (length)
           (rsa-generate-key length
                             +RSA_F4+
                             (cffi:null-pointer)
                             (cffi:null-pointer))))
    (cond ((= key-length 512)
           (unless *tmp-rsa-key-512*
             (setf *tmp-rsa-key-512* (rsa-key key-length)))
           *tmp-rsa-key-512*)
          ((= key-length 1024)
           (unless *tmp-rsa-key-1024*
             (setf *tmp-rsa-key-1024* (rsa-key key-length)))
           *tmp-rsa-key-1024*)
          (t
           (unless *tmp-rsa-key-2048*
             (setf *tmp-rsa-key-2048* (rsa-key key-length)))
           *tmp-rsa-key-2048*))))

;;; Funcall wrapper
;;;
(defvar *socket*)

(declaim (inline ensure-ssl-funcall))
(defun ensure-ssl-funcall (stream handle func &rest args)
  (loop
    (let ((nbytes
            (let ((*socket* (ssl-stream-socket stream))) ;for Lisp-BIO callbacks
              (apply func args))))
      (when (plusp nbytes)
        (return nbytes))
      (let ((error (ssl-get-error handle nbytes)))
        (case error
          (#.+ssl-error-want-read+
           (io-wait stream (ssl-get-fd handle) :input))
          (#.+ssl-error-want-write+
           (io-wait stream (ssl-get-fd handle) :output))
          (t
            (ssl-signal-error handle func error nbytes)))))))

(declaim (inline nonblocking-ssl-funcall))
(defun nonblocking-ssl-funcall (stream handle func &rest args)
  (loop
     (let ((nbytes
      (let ((*socket* (ssl-stream-socket stream))) ;for Lisp-BIO callbacks
        (apply func args))))
       (when (plusp nbytes)
   (return nbytes))
       (let ((error (ssl-get-error handle nbytes)))
   (case error
     ((#.+ssl-error-want-read+ #.+ssl-error-want-write+)
      (return nbytes))
     (t
      (ssl-signal-error handle func error nbytes)))))))


;;; Waiting for input/output to be possible

(defun deadline->timeout (deadline)
  (/ (- deadline (get-internal-real-time))
     internal-time-units-per-second))

#+clozure-common-lisp
(defun io-wait (stream fd direction)
  (let ((socket (ssl-stream-socket stream))
        (deadline (ssl-stream-deadline stream)))
    (unless deadline
      (setf deadline (stream-deadline socket)))
    (let ((timeout (ecase direction
                     (:input (stream-input-timeout socket))
                     (:output (stream-output-timeout socket))))
          (deadline-timeout (when deadline
                              (deadline->timeout deadline)))
          (timeout-error (case direction
                           (:input 'ccl::input-timeout)
                           (:output 'ccl::output-timeout))))
      (when (and deadline-timeout (minusp deadline-timeout))
        (error 'ccl::communication-deadline-expired :stream stream))
      (when (and timeout (minusp timeout))
        (error timeout-error :stream stream))
      (when (or (not timeout)
                (and deadline-timeout
                     (< deadline-timeout timeout)))
        (setf timeout deadline-timeout
              timeout-error 'ccl::communication-deadline-expired))
      (when timeout
        (setf timeout (round (* 1000 timeout))))
      (multiple-value-bind (win timedout error)
          (case direction
            (:input (ccl::process-input-wait fd timeout))
            (:output (ccl::process-output-wait fd timeout)))
        (unless win
          (if timedout
            (error timeout-error :stream stream)
            (ccl::stream-io-error stream (- error) "read")))))))

#+sbcl
(defun io-wait (stream fd direction)
  (let ((timeout (let ((socket (ssl-stream-socket stream)))
                   (ecase direction
                     (:input (stream-input-timeout socket))
                     (:output (stream-output-timeout socket))))))
    (when (or (and timeout (minusp timeout))
              (not (sb-sys:wait-until-fd-usable fd direction timeout)))
      (error 'sb-sys:io-timeout :seconds timeout))))

#-(or clozure-common-lisp sbcl)
(defun io-wait (stream fd direction)
  (declare (ignore stream fd direction))
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
  (declare (ignore rwflag unused))
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
         (buf (cffi:make-shareable-byte-vector length)))
    (dotimes (i length)
      (setf (elt buf i) (elt seed-byte-sequence i)))
    (cffi:with-pointer-to-vector-data (ptr buf)
      (rand-seed ptr length))))

(defun ssl-ctx-set-session-cache-mode (ctx mode)
  (ssl-ctx-ctrl ctx +SSL_CTRL_SET_SESS_CACHE_MODE+ mode (cffi:null-pointer)))

(defun ssl-set-tlsext-host-name (ctx hostname)
  (ssl-ctrl ctx 55 #|SSL_CTRL_SET_TLSEXT_HOSTNAME|# 0 #|TLSEXT_NAMETYPE_host_name|# hostname))

(defvar *locks*)
(defconstant +CRYPTO-LOCK+ 1)
(defconstant +CRYPTO-UNLOCK+ 2)
(defconstant +CRYPTO-READ+ 4)
(defconstant +CRYPTO-WRITE+ 8)

;; zzz as of early 2011, bxthreads is totally broken on SBCL wrt. explicit
;; locking of recursive locks.  with-recursive-lock works, but acquire/release
;; don't.  Hence we use non-recursize locks here (but can use a recursive
;; lock for the global lock).

(cffi:defcallback locking-callback :void
    ((mode :int)
     (n :int)
     (file :pointer) ;; could be (file :string), but we don't use FILE, so avoid the conversion
     (line :int))
  (declare (ignore file line))
  ;; (assert (logtest mode (logior +CRYPTO-READ+ +CRYPTO-WRITE+)))
  (let ((lock (elt *locks* n)))
    (cond
      ((logtest mode +CRYPTO-LOCK+)
       (bt:acquire-lock lock))
      ((logtest mode +CRYPTO-UNLOCK+)
       (bt:release-lock lock))
      (t
       (error "fell through")))))

(defvar *threads* (trivial-garbage:make-weak-hash-table :weakness :key))
(defvar *thread-counter* 0)

(defparameter *global-lock*
  (bordeaux-threads:make-recursive-lock "SSL initialization"))

;; zzz BUG: On a 32-bit system and under non-trivial load, this counter
;; is likely to wrap in less than a year.
(cffi:defcallback threadid-callback :unsigned-long ()
  (bordeaux-threads:with-recursive-lock-held (*global-lock*)
    (let ((self (bt:current-thread)))
      (or (gethash self *threads*)
    (setf (gethash self *threads*)
    (incf *thread-counter*))))))

(defvar *ssl-check-verify-p* :unspecified
  "DEPRECATED.
Use the (MAKE-SSL-CLIENT-STREAM .. :VERIFY ?) to enable/disable verification.
MAKE-CONTEXT also allows to enab/disable verification.")

(defun default-ssl-method ()
  (if (openssl-is-at-least 1 1)
      'tls-method
      'ssl-v23-method))

(defun initialize (&key method rand-seed)
  (when (or (openssl-is-not-even 1 1)
            ;; Old versions of LibreSSL
            ;; require this initialization
            ;; (https://github.com/cl-plus-ssl/cl-plus-ssl/pull/91),
            ;; new versions keep this API backwards
            ;; compatible so we can call it too.
            (libresslp))
    (setf *locks* (loop
                     repeat (crypto-num-locks)
                     collect (bt:make-lock)))
    (crypto-set-locking-callback (cffi:callback locking-callback))
    (crypto-set-id-callback (cffi:callback threadid-callback))
    (ssl-load-error-strings)
    (ssl-library-init))
  (setf *bio-lisp-method* (make-bio-lisp-method))
  (when rand-seed
    (init-prng rand-seed))
  (setf *ssl-check-verify-p* :unspecified)
  (setf *ssl-global-method* (funcall (or method (default-ssl-method))))
  (setf *ssl-global-context* (ssl-ctx-new *ssl-global-method*))
  (unless (eql 1 (ssl-ctx-set-default-verify-paths *ssl-global-context*))
    (error "ssl-ctx-set-default-verify-paths failed."))
  (ssl-ctx-set-session-cache-mode *ssl-global-context* 3)
  (ssl-ctx-set-default-passwd-cb *ssl-global-context*
                                 (cffi:callback pem-password-callback))
  (when (or (openssl-is-not-even 1 1)
            ;; Again, even if newer LibreSSL
            ;; don't need this call, they keep
            ;; the API compatibility so we can continue
            ;; making this call.
            (libresslp))
    (ssl-ctx-set-tmp-rsa-callback *ssl-global-context*
                                  (cffi:callback tmp-rsa-callback))))

(defun ensure-initialized (&key method (rand-seed nil))
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
  #+lispworks
  (check-cl+ssl-symbols)
  (bordeaux-threads:with-recursive-lock-held (*global-lock*)
    (unless (ssl-initialized-p)
      (initialize :method method :rand-seed rand-seed))
    (unless *bio-lisp-method*
      (setf *bio-lisp-method* (make-bio-lisp-method)))))

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
  (if *ssl-global-context*
      (ssl-ctx-free *ssl-global-context*))
  (unless (member :cl+ssl-foreign-libs-already-loaded
                  *features*)
    (cffi:use-foreign-library libcrypto)
    (cffi:load-foreign-library 'libssl))
  (setf *ssl-global-context* nil)
  (setf *ssl-global-method* nil)
  (setf *tmp-rsa-key-512* nil)
  (setf *tmp-rsa-key-1024* nil))
