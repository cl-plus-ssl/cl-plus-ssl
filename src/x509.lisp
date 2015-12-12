(in-package :cl+ssl)

;; ffi
;; X509 *d2i_X509(X509 **px, const unsigned char **in, int len);

(cffi:defcfun ("X509_free" x509-free)
    :void
  (x509 :pointer))

(cffi:defcfun ("X509_NAME_oneline" x509-name-oneline)
    :pointer
  (x509-name :pointer)
  (buf :pointer)
  (size :int))

(cffi:defcfun ("X509_NAME_get_index_by_NID" x509-name-get-index-by-nid)
    :int
  (name :pointer)
  (nid :int)
  (lastpos :int))

(cffi:defcfun ("X509_NAME_get_entry" x509-name-get-entry)
    :pointer
  (name :pointer)
  (log :int))

(cffi:defcfun ("X509_NAME_ENTRY_get_data" x509-name-entry-get-data)
    :pointer
  (name-entry :pointer))

(cffi:defcfun ("X509_get_issuer_name" x509-get-issuer-name)
    :pointer                            ; *X509_NAME
  (x509 :pointer))

(cffi:defcfun ("X509_get_subject_name" x509-get-subject-name)
    :pointer                            ; *X509_NAME
  (x509 :pointer))

(cffi:defcfun ("X509_get_ext_d2i" x509-get-ext-d2i)
    :pointer
  (cert :pointer)
  (nid :int)
  (crit :pointer)
  (idx :pointer))

(cffi:defcfun ("X509_STORE_CTX_get_error" x509-store-ctx-get-error)
    :int
  (ctx :pointer))

(cffi:defcfun ("d2i_X509" d2i-x509)
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

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defconstant +V-ASN1-OCTET-STRING+ 4)
  (defconstant +V-ASN1-UTF8STRING+ 12)
  (defconstant +V-ASN1-PRINTABLESTRING+ 19)
  (defconstant +V-ASN1-TELETEXSTRING+ 20)
  (defconstant +V-ASN1-IASTRING+ 22)
  (defconstant +V-ASN1-UNIVERSALSTRING+ 28)
  (defconstant +V-ASN1-BMPSTRING+ 30))


(defconstant +NID-subject-alt-name+ 85)
(defconstant +NID-commonName+   13)

(cffi:defcstruct general-name
  (type :int)
  (data :pointer))

(cffi:defcfun ("sk_value" sk-value)
    :pointer
  (stack :pointer)
  (index :int))

(cffi:defcfun ("sk_num" sk-num)
    :int
  (stack :pointer))

(declaim (ftype (function (cffi:foreign-pointer fixnum) cffi:foreign-pointer) sk-general-name-value))
(defun sk-general-name-value (names index)
  (sk-value names index))

(declaim (ftype (function (cffi:foreign-pointer) fixnum) sk-general-name-num))
(defun sk-general-name-num (names)
  (sk-num names))

(cffi:defcfun ("GENERAL_NAMES_free" general-names-free)
    :void
  (general-names :pointer))

(cffi:defcfun ("ASN1_STRING_data" asn1-string-data)
    :pointer
  (asn1-string :pointer))

(cffi:defcfun ("ASN1_STRING_length" asn1-string-length)
    :int
  (asn1-string :pointer))

(cffi:defcfun ("ASN1_STRING_type" asn1-string-type)
    :int
  (asn1-string :pointer))

(cffi:defcfun ("strlen" strlen)
    :int
  (string :string))

(cffi:defcstruct asn1_string_st
  (length :int)
  (type :int)
  (data :pointer)
  (flags :long))

(defgeneric decode-asn1-string (asn1-string type))

(defmethod decode-asn1-string (asn1-string (type (eql #.+v-asn1-iastring+)))
  (let* ((data (asn1-string-data asn1-string))
         (length (asn1-string-length asn1-string))
         (strlen (strlen data)))
    (when (= strlen length)
      (cffi:foreign-string-to-lisp data))))

(defmethod decode-asn1-string (asn1-string (type (eql #.+v-asn1-printablestring+)))
  (let* ((data (asn1-string-data asn1-string))
         (length (asn1-string-length asn1-string))
         (strlen (strlen data)))
    (when (= strlen length)
      (cffi:foreign-string-to-lisp data))))

(defmethod decode-asn1-string (asn1-string (type (eql #.+v-asn1-utf8string+)))
  (let* ((data (asn1-string-data asn1-string))
         (length (asn1-string-length asn1-string))
         (strlen (strlen data)))
    (when (= strlen length)
      (cffi:foreign-string-to-lisp data))))

(defmethod decode-asn1-string (asn1-string (type (eql #.+v-asn1-universalstring+)))
  (let* ((data (asn1-string-data asn1-string))
         (length (asn1-string-length asn1-string)))
    (when (= 0 (mod length 4))
      (cffi:foreign-string-to-lisp data :encoding :utf-32))))

(defmethod decode-asn1-string (asn1-string (type (eql #.+v-asn1-teletexstring+)))
  (let* ((data (asn1-string-data asn1-string))
         (length (asn1-string-length asn1-string))
         (strlen (strlen data)))
    (when (= strlen length)
      (cffi:foreign-string-to-lisp data))))

(defmethod decode-asn1-string (asn1-string (type (eql #.+v-asn1-bmpstring+)))
  (let* ((data (asn1-string-data asn1-string))
         (length (asn1-string-length asn1-string)))
    (when (= 0 (mod length 2))
      (cffi:foreign-string-to-lisp data :encoding :utf-16))))

;; TODO: respect asn1-string type
(defun try-get-asn1-string-data (asn1-string allowed-types)
  (let ((type (asn1-string-type asn1-string)))
    (assert (member (asn1-string-type asn1-string) allowed-types) nil "Invalid asn1 string type")
    (decode-asn1-string asn1-string type)))

(defun slurp-stream (stream)
  (let ((seq (make-buffer (file-length stream))))
    (read-sequence seq stream)
    seq))

(defmethod decode-certificate ((format (eql :der)) bytes)
  (with-pointer-to-vector-data (buf* bytes)
    (cffi:with-foreign-object (buf** :pointer)
      (setf (cffi:mem-ref buf** :pointer) buf*)
      (d2i-x509 (cffi:null-pointer) buf** (length bytes)))))

(defun cert-format-from-path (path)
  ;; or match "pem" type too and raise unknown format error?
  (if (equal "der" (pathname-type path))
      :der
      :pem))

(defun decode-certificate-from-file (path &key format)
  (let ((bytes (with-open-file (stream path :element-type '(unsigned-byte 8))
                 (slurp-stream stream)))
        (format (or format (cert-format-from-path path))))
    (decode-certificate format bytes)))

(defun certificate-alt-names (cert)
  (x509-get-ext-d2i cert +NID-subject-alt-name+ (cffi:null-pointer) (cffi:null-pointer)))

(defun certificate-dns-alt-names (cert)
  (let ((altnames (certificate-alt-names cert)))
    (unless (cffi:null-pointer-p altnames)
      (unwind-protect
           (flet ((alt-name-to-string (alt-name)
                    (cffi:with-foreign-slots ((type data) alt-name (:struct general-name))
                      (when (= type +GEN-DNS+)
                        (if-let ((string (try-get-asn1-string-data data '(#.+v-asn1-iastring+))))
                          string
                          (error "Malformed certificate: possibly NULL in dns-alt-name"))))))
             (let ((altnames-count (sk-general-name-num altnames)))
               (loop for i from 0 below altnames-count
                     as alt-name = (sk-general-name-value altnames i)
                     collect (alt-name-to-string alt-name))))
        (general-names-free altnames)))))

(defun certificate-subject-common-names (cert)
  (let ((i -1)
        (subject-name (x509-get-subject-name cert)))
    (flet ((extract-cn ()
             (setf i (x509-name-get-index-by-nid subject-name +NID-commonName+ i))
             (when (>= i 0)
               (let* ((entry (x509-name-get-entry subject-name i)))
                 (try-get-asn1-string-data (x509-name-entry-get-data entry) '(#.+v-asn1-utf8string+
                                                                              #.+v-asn1-bmpstring+
                                                                              #.+v-asn1-printablestring+
                                                                              #.+v-asn1-universalstring+
                                                                              #.+v-asn1-teletexstring+))))))
      (loop
        as cn = (extract-cn)
        if cn collect cn
        if (not cn) do
           (loop-finish)))))
