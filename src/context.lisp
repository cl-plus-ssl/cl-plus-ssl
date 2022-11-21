;;;; -*- Mode: LISP; Syntax: COMMON-LISP; indent-tabs-mode: nil; coding: utf-8; show-trailing-whitespace: t -*-
;;;
;;; Copyright (C) contributors as per cl+ssl git history
;;;
;;; See LICENSE for details.

(in-package :cl+ssl)

(define-condition verify-location-not-found-error (ssl-error)
  ((location :initarg :location))
  (:documentation "Unable to find verify locations")
  (:report (lambda (condition stream)
             (format stream "Unable to find verify location. Path: ~A" (slot-value condition 'location)))))

(defun validate-verify-location (location)
  (handler-case
      (cond
        ((uiop:file-exists-p location)
         (values location t))
        ((uiop:directory-exists-p location)
         (values location nil))
        (t
         (error 'verify-location-not-found-error :location location)))))

(defun add-verify-locations (ctx locations)
  (dolist (location locations)
    (multiple-value-bind (location isfile)
        (validate-verify-location location)
      (cffi:with-foreign-strings ((location-ptr location))
        (unless (= 1 (cl+ssl::ssl-ctx-load-verify-locations
                      ctx
                      (if isfile location-ptr (cffi:null-pointer))
                      (if isfile (cffi:null-pointer) location-ptr)))
          (error 'ssl-error :queue (read-ssl-error-queue) :message (format nil "Unable to load verify location ~A" location)))))))

(defun ssl-ctx-set-verify-location (ctx location)
  (cond
    ((eq :default location)
     (unless (= 1 (ssl-ctx-set-default-verify-paths ctx))
       (error 'ssl-error-call
              :queue (read-ssl-error-queue)
              :message (format nil "Unable to load default verify paths"))))
     ((eq :default-file location)
      ;; supported since openssl 1.1.0
      (unless (= 1 (ssl-ctx-set-default-verify-file ctx))
        (error 'ssl-error-call
               :queue (read-ssl-error-queue)
               :message (format nil "Unable to load default verify file"))))
     ((eq :default-dir location)
      ;; supported since openssl 1.1.0
      (unless (= 1 (ssl-ctx-set-default-verify-dir ctx))
        (error 'ssl-error-call
               :queue (read-ssl-error-queue)
               :message (format nil "Unable to load default verify dir"))))
    ((stringp location)
     (add-verify-locations ctx (list location)))
    ((pathnamep location)
     (add-verify-locations ctx (list location)))
    ((and location (listp location))
     (add-verify-locations ctx location))
    ;; silently allow NIL as location
    (location
     (error "Invalid location ~a" location))))

(alexandria:define-constant +default-cipher-list+
    (format nil
            "ECDHE-RSA-AES256-GCM-SHA384:~
            ECDHE-RSA-AES256-SHA384:~
            ECDHE-RSA-AES256-SHA:~
            ECDHE-RSA-AES128-GCM-SHA256:~
            ECDHE-RSA-AES128-SHA256:~
            ECDHE-RSA-AES128-SHA:~
            ECDHE-RSA-RC4-SHA:~
            DHE-RSA-AES256-GCM-SHA384:~
            DHE-RSA-AES256-SHA256:~
            DHE-RSA-AES256-SHA:~
            DHE-RSA-AES128-GCM-SHA256:~
            DHE-RSA-AES128-SHA256:~
            DHE-RSA-AES128-SHA:~
            AES256-GCM-SHA384:~
            AES256-SHA256:~
            AES256-SHA:~
            AES128-GCM-SHA256:~
            AES128-SHA256:~
            AES128-SHA") :test 'equal)

(cffi:defcallback verify-peer-callback :int ((ok :int) (ctx :pointer))
  (let ((error-code (x509-store-ctx-get-error ctx)))
    (unless (= error-code 0)
      (error 'ssl-error-verify  :error-code error-code))
    ok))

(defun make-context (&key (method nil method-supplied-p)
                          disabled-protocols
                          (options (list +SSL-OP-ALL+))
                          min-proto-version
                          (session-cache-mode +ssl-sess-cache-server+)
                          (verify-location :default)
                          (verify-depth 100)
                          (verify-mode +ssl-verify-peer+)
                          (verify-callback nil verify-callback-supplied-p)
                          (cipher-list +default-cipher-list+)
                          (pem-password-callback 'pem-password-callback)
                          certificate-chain-file
                          private-key-file
                          private-key-password
                          (private-key-file-type +ssl-filetype-pem+))
  "Creates a new SSL_CTX using SSL_CTX_new and initializes it according to
the specified parameters.

After you're done using the context, don't forget to free it using SSL-CTX-FREE.

Exceptions:

    SSL-ERROR-INITIALIZE. When underlying SSL_CTX_new fails.

Keyword arguments:

    METHOD. Specifies which supported SSL/TLS to use.
        If not specified then TLS_method is used on OpenSSL
        versions supporing it (on legacy versions SSLv23_method is used).

    DISABLED-PROTOCOLS. List of +SSL-OP-NO-* constants. Denotes
        disabled SSL/TLS versions. When method not specified
        defaults to (list +SSL-OP-NO-SSLv2+ +SSL-OP-NO-SSLv3+)

    OPTIONS. SSL context options list. Defaults to (list +SSL-OP-ALL+)

    SESSION-CACHE-MODE. Enable/Disable session caching.
        Defaults to +SSL-SESS-CACHE-SERVER+

    VERIFY-LOCATION. Location(s) to load CA from.

        Possible values:
            :DEFAULT OpenSSL default directory and file will be loaded
            :DEFAULT-FILE OpenSSL default file will be loaded. Requires OpenSSL >= 1.1.0.
            :DEFAULT-DIR OpenSSL default directory will be loaded. Requires OpenSSL >= 1.1.0.
            STRING Directory or file path to be loaded
            PATHNAME Directory or file path to be loaded
            (LIST (OR STRING PATHNAME)) List of directories or files to be loaded

    VERIFY-DEPTH. Sets the maximum depth for the certificate chain verification
        that shall be allowed for context. Defaults to 100.

    VERIFY-MODE. Sets the verification flags for context to be mode.
        Available flags

            +SSL-VERIFY-NONE+
            +SSL-VERIFY-PEER+
            +SSL-VERIFY-FAIL-IF-NO-PEER-CERT+
            +SSL-VERIFY-CLIENT-ONCE+

        Defaults to +VERIFY-PEER+

    VERIFY-CALLBACK. The verify-callback is used to control the behaviour
        when the +SSL-VERIFY-PEER+ flag is set.
        Please note: this must be CFFI callback i.e. defined as
        (DEFCALLBACK :INT ((OK :INT) (CTX :POINTER)) .. ).
        Defaults to verify-peer-callback which converts chain errors
        to ssl-error-verify.

    CIPHER-LIST. Sets the list of available ciphers for context.
        Possible values described here:
        https://www.openssl.org/docs/manmaster/apps/ciphers.html.
        Default is expected to change overtime to provide highest security level.
        Do not rely on its exact value.

    PEM-PASSWORD-CALLBACK. Sets the default password callback called when
        loading/storing a PEM certificate with encryption.
        Please note: this must be CFFI callback i.e. defined as
        (CFFI:DEFCALLBACK :INT ((BUF :POINTER) (SIZE :INT) (RWFLAG :INT) (UNUSED :POINTER)) .. ).
        Defaults to PEM-PASSWORD-CALLBACK which simply uses password
        provided by WITH-PEM-PASSWORD.
"
  (ensure-initialized)
  (let ((ctx (ssl-ctx-new (if method-supplied-p
                              method
                              (progn
                                (unless disabled-protocols
                                  (setf disabled-protocols
                                        (list +SSL-OP-NO-SSLv2+ +SSL-OP-NO-SSLv3+)))
                                (funcall (default-ssl-method)))))))
    (when (cffi:null-pointer-p ctx)
      (error 'ssl-error-initialize :reason "Can't create new SSL CTX" :queue (read-ssl-error-queue)))
    (handler-bind ((error (lambda (_)
                            (declare (ignore _))
                            (ssl-ctx-free ctx))))
      (ssl-ctx-set-options ctx (apply #'logior (append disabled-protocols options)))
      ;; Older OpenSSL versions might not have this SSL_ctrl call.
      ;; Having them error out is a sane default - it's better than to keep
      ;; on running with insecure values.
      ;; People that _have_ to use much too old OpenSSL versions will
      ;; have to call MAKE-CONTEXT with :MIN-PROTO-VERSION nil.
      ;;
      ;; As an aside: OpenSSL had the "SSL_OP_NO_TLSv1_2" constant since
      ;;   7409d7ad517    2011-04-29 22:56:51 +0000
      ;; so requiring a "new"er OpenSSL to match CL+SSL's defauls shouldn't be a problem.
      (if min-proto-version
        (if (zerop (ssl-ctx-set-min-proto-version ctx min-proto-version))
          (error "Couldn't set minimum SSL protocol version!")))
      (ssl-ctx-set-session-cache-mode ctx session-cache-mode)
      (ssl-ctx-set-verify-location ctx verify-location)
      (ssl-ctx-set-verify-depth ctx verify-depth)
      (ssl-ctx-set-verify ctx verify-mode (if verify-callback
                                              (cffi:get-callback verify-callback)
                                              (if verify-callback-supplied-p
                                                  (cffi:null-pointer)
                                                  (if (= verify-mode +ssl-verify-peer+)
                                                      (cffi:callback verify-peer-callback)
                                                      (cffi:null-pointer)))))
      (ssl-ctx-set-cipher-list ctx cipher-list)
      (ssl-ctx-set-default-passwd-cb ctx (cffi:get-callback pem-password-callback))
      (when certificate-chain-file
        (ssl-ctx-use-certificate-chain-file ctx certificate-chain-file))
      (when private-key-file
        (with-pem-password (private-key-password)
          (ssl-ctx-use-privatekey-file ctx private-key-file private-key-file-type)))
      ctx)))

(defun call-with-global-context (context auto-free-p body-fn)
  (let* ((*ssl-global-context* context))
    (unwind-protect (funcall body-fn)
      (when auto-free-p
        (ssl-ctx-free context)))))

(defmacro with-global-context ((context &key auto-free-p) &body body)
  "Executes the BODY with *SSL-GLOBAL-CONTEXT* bound to the CONTEXT.
If AUTO-FREE-P is true the context is freed using SSL-CTX-FREE before exit. "
  `(call-with-global-context ,context ,auto-free-p (lambda () ,@body)))
