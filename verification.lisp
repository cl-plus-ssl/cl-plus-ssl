;;; Copyright (C) 2014  Ilya Khaprov https://github.com/deadtrickster
;;;
;;; See LICENSE for details.

#+xcvb
(module
 (:depends-on ("package" "conditions" "ffi")))

;; (eval-when (:compile-toplevel)
;;   (declaim
;;    (optimize (speed 3) (space 1) (safety 1) (debug 0) (compilation-speed 0))))


(in-package :cl+ssl)

;;; waiting for 1.0.2
;; (defconstant +X509-CHECK-FLAG-ALWAYS-CHECK-SUBJECT+ #x01
;;   "The X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT flag causes the function to consider the subject
;; DN even if the certificate contains at least one subject alternative name of the right type
;; (DNS name or email address as appropriate); the default is to ignore the subject DN when at
;; least one corresponding subject alternative names is present.")
;; (defconstant +X509-CHECK-FLAG-NO-WILDCARDS+ #x02
;;   "Disable wildcard matching for dnsName fields and common name. Check_host only")
;; (defconstant +X509-CHECK-FLAG-NO-PARTIAL-WILDCARDS+ #x04
;;   "Suppresses support for \"*\" as wildcard pattern in labels that have a prefix or suffix,
;; such as: \"www*\" or \"*www\". Check_host only")
;; (defconstant +X509-CHECK-FLAG-MULTI-LABEL-WILDCARDS+ #x08
;;   "Allows a \"*\" that constitutes the complete label of a DNS name (e.g. \"*.example.com\")
;; to match more than one label in name. Check_host only")
;; (defconstant +X509-CHECK-FLAG-SINGLE-LABEL-SUBDOMAINS+ #x10
;;   "Restricts name values which start with \".\", that would otherwise match any sub-domain
;; in the peer certificate, to only match direct child sub-domains. Thus, for instance, with
;; this flag set a name of \".example.com\" would match a peer certificate with a DNS name of
;; \"www.example.com\", but would not match a peer certificate with a DNS name of \"www.sub.example.com\".
;; Check_host only")

;; ;; waiting for 1.0.2
;; (defun add-host-verification (ctx host-name flags)
;;   (let ((x509-vp))
;;     (unwind-protect
;;          (progn
;;            (setq x509-vp (X509-VERIFY-PARAM-new))
;;            (cffi:with-foreign-string (name host-name)
;;              (X509-Verify-param-set1-host x509-vp name 0)
;;              (X509-verify-param-set-hostflags x509-vp flags)
;;              (ssl-ctx-set1-param ctx x509-vp)))
;;       (if x509-vp
;;           (X509-VERIFY-PARAM-free x509-vp)))))

(cffi:defcallback cb-ssl-verify :int ((ok :int) (ctx :pointer))
  (let* (;(certificate (X509-STORE-CTX-get-current-cert ctx))
        (error-code (X509_STORE_CTX-get-error ctx)))
    (unless (eql error-code 0)
      (error 'ssl-error-verify  :error-code error-code))
    ok))

(cffi:defcfun ("sk_value" sk-value)
    :pointer
  (stack :pointer)
  (index :int))

(cffi:defcfun ("sk_num" sk-num)
    :int
  (stack :pointer))

(cffi:defcfun ("X509_NAME_get_index_by_NID" x509-name-get-index-by-nid)
    :int
  (name :pointer)
  (nid :int)
  (lastpost :int))

(cffi:defcfun ("X509_NAME_get_entry" x509-name-get-entry)
    :pointer
  (name :pointer)
  (log :int))

(cffi:defcfun ("X509_NAME_ENTRY_get_data" x509-name-entry-get-data)
    :pointer
  (name-entry :pointer))

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

(defun sk-general-name-value (names index)
  (sk-value names index))

(defun sk-general-name-num (names)
  (sk-num names))

(cffi:defcstruct asn1_string_st
  (length :int)
  (type :int)
  (data :pointer)
  (flags :long))

(cffi:defcstruct GENERAL_NAME
  (type :int)
  (data :pointer))

(defun remove-trailing-dot (str)
  (if (eql (elt str (1- (length str))) #\.)
      (subseq str 0 (- (length str) 2))
      str))


#|
http://tools.ietf.org/html/rfc6125

1.  The client SHOULD NOT attempt to match a presented identifier in
which the wildcard character comprises a label other than the
left-most label (e.g., do not match bar.*.example.net).

2.  If the wildcard character is the only character of the left-most
label in the presented identifier, the client SHOULD NOT compare
against anything but the left-most label of the reference
identifier (e.g., *.example.com would match foo.example.com but
not bar.foo.example.com or example.com).

3.  The client MAY match a presented identifier in which the wildcard
character is not the only character of the label (e.g.,
baz*.example.net and *baz.example.net and b*z.example.net would
be taken to match baz1.example.net and foobaz.example.net and
buzz.example.net, respectively).  However, the client SHOULD NOT
attempt to match a presented identifier where the wildcard
character is embedded within an A-label or U-label [IDNA-DEFS] of
an internationalized domain name [IDNA-PROTO].
|#

(defun try-match-using-wildcards (hostname pattern)
  (let ((pattern-w-pos (position #\* pattern))
        (pattern-leftmost-label-end)
        (hostname-leftmost-label-end))
    (unless pattern-w-pos
      (return-from try-match-using-wildcards nil))

    ;; TODO: detect if hostname is IP address

    (setq pattern-leftmost-label-end (position #\. pattern))
    (when (or (null pattern-leftmost-label-end) (null (position #\. pattern :start (1+ pattern-leftmost-label-end)))
              (> pattern-w-pos pattern-leftmost-label-end)
              (string= pattern "xn--" :end1 4))
      (return-from try-match-using-wildcards nil))

    (setf hostname-leftmost-label-end (position #\. hostname))
    (when (or (null hostname-leftmost-label-end) (not (string= hostname pattern :start1 hostname-leftmost-label-end
                                                                                :start2 pattern-leftmost-label-end)))

      (return-from try-match-using-wildcards nil))


    (when (< hostname-leftmost-label-end pattern-leftmost-label-end)
      (return-from try-match-using-wildcards nil))

    t))

(defun verify-hostname% (hostname pattern)
  (log:debug "Verifying ~A against ~A" hostname pattern)
  (setf hostname (remove-trailing-dot hostname)
        pattern (remove-trailing-dot pattern))
  (if (string= hostname pattern)
      t
      (try-match-using-wildcards hostname pattern)))

(defun try-get-asn1-string-data (asn1-string) ;; as for now valid for GEN_DNS GEN_EMAIL etc..
  (cffi:with-foreign-slots ((length data) asn1-string (:struct asn1_string_st))
    (let* ((strlen (strlen data)))
      (when (= strlen length)
        (cffi:foreign-string-to-lisp data)))))

(defun try-match-alt-name (certificate hostname)
  (let ((altnames (x509-get-ext-d2i certificate 85 #|NID_subject_alt_name|# (cffi:null-pointer) (cffi:null-pointer)))
        (matched nil)
        (alt-names-collection (list)))
    (if (not (cffi:null-pointer-p altnames))
        (prog1
            (let ((altnames-count (sk-general-name-num altnames)))
              (do ((i 0 (1+ i)))
                  ((or (eq t matched) (>= i  altnames-count)) matched)
                (let* ((name (sk-general-name-value altnames i))
                       (dns-name))
                  (cffi:with-foreign-slots ((type data) name (:struct general_name))
                    (when (= type 2 #|GEN_DNS|#)
                      (setq dns-name (try-get-asn1-string-data data))
                      (when dns-name
                        (setf alt-names-collection (append alt-names-collection (list dns-name)))
                        (setq matched (if (verify-hostname% hostname dns-name) t :no-alt-match))))))))
          ;; turns out sk_GENERAL_NAME_pop_free is layered #define mess, don't know what to do now
          ;;(sk_GENERAL_NAME_pop_free altnames 1216 #|GENERAL_NAME_free|#)
          ))
    (if (eq :no-alt-match matched)
        (error 'ssl-unable-to-match-alternative-name :hostname hostname
                                                     :found-alt-names alt-names-collection)
        matched)))

(defun get-common-name-index (certificate)
  (x509-name-get-index-by-nid (x509-get-subject-name certificate) 13 #|NID_commonName|# -1))

(defun get-common-name-entry (certificate index)
  (x509-name-get-entry (x509-get-subject-name certificate) index))

(defun try-match-common-name (certificate hostname)
  (log:info "try-match-common-name")
  (let (common-name-index
        common-name-entry
        common-name-asn1
        dns-name)
    (setf common-name-index (get-common-name-index certificate))
    (unless common-name-index
      (error 'ssl-unable-to-obtain-common-name))
    (setf common-name-entry (get-common-name-entry certificate common-name-index))
    (unless common-name-entry
      (error 'ssl-unable-to-obtain-common-name))
    (setf common-name-asn1 (x509-name-entry-get-data common-name-entry))
    (unless common-name-asn1
      (error 'ssl-unable-to-obtain-common-name))
    (setq dns-name (try-get-asn1-string-data common-name-asn1))
    (unless dns-name
      (error 'ssl-unable-to-obtain-common-name))
    (unless (verify-hostname% hostname dns-name)
      (error 'ssl-unable-to-match-common-name :hostname hostname :found-common-name dns-name))))

(defun get-alt-names (certificate alt-name-type)
  (let ((altnames (x509-get-ext-d2i certificate 85 #|NID_subject_alt_name|# (cffi:null-pointer) (cffi:null-pointer))))
    (alt-names-collection (list)))
  (if (not (cffi:null-pointer-p altnames))
      (prog1
          (let ((altnames-count (sk-general-name-num altnames)))
            (do ((i 0 (1+ i)))
                ((or (eq t matched) (>= i  altnames-count)) alt-names-collection)
              (let* ((alt-name (sk-general-name-value altnames i))
                     (alt-name-string))
                (cffi:with-foreign-slots ((type data) alt-name (:struct general_name))
                  (when (= type alt-name-type)
                    (setq alt-name-string (try-get-asn1-string-data data)) 
                    (when alt-name-string
                      (setf alt-names-collection (append alt-names-collection (listcheck-string)))))))))
        ;; turns out sk_GENERAL_NAME_pop_free is layered #define mess, don't know what to do now
        ;;(sk_GENERAL_NAME_pop_free altnames 1216 #|GENERAL_NAME_free|#)
        )))

(()

(defun do-x509-check (certificate chk type &key (always-check-subject t)
                                                (no-wildcards nil)
                                                (no-partial-wildcards t)
                                                (multi-label-wildcards nil)
                                                (single-label-subdomain t))

  (let ((altnames (get-alt-names certificate type))
        common-name-id
        asn1-string-type
        equality-function)
    (case type
      (+GEN-EMAIL+
       (setf common-name-id +NID-pks9-emailAddress
             asn1-string-type +V-ASN1-IASTRING+
             equality-function 'equal-email))
      (+GEN-DNS+
       (setf common-name-id +NID-commonName+
             asn1-string-type +V-ASN1-IASTRING+
             equality-function (if no-wildcards
                                   'equal-nocase
                                   'equal-wildcard)))
      (t (setf alt-type +V-ASN1-OCTET-STRING+
               equality-function equal-case)))
    
    (if (= 0 (length altnames)
           (if (or (not common-name-id) (not always-check-subject))
               (values :no-alt-match altnames)
               (let ((common-name (get-common-name certificate)))
                 (if common-name
                     (try-match common-name chk type asn1-string-type equality-function
                                :always-check-subject always-check-subject
                                :no-wildcards no-wildcards
                                :no-partial-wildcards no-partial-wildcards
                                :multi-label-wildcards multi-label-wildcards
                                :single-label-subdomain single-label-subdomain)
                     (values :no-common-name))))
           (let ((check-result))
             (dolist (altname altnames check-result)
               (try-match alt-name chk type asn1-string-type equality-function
                          :always-check-subject always-check-subject
                          :no-wildcards no-wildcards
                          :no-partial-wildcards no-partial-wildcards
                          :multi-label-wildcards multi-label-wildcards
                          :single-label-subdomain single-label-subdomain)))))))


(defun verify-hostname (certificate hostname &key (always-check-subject t)
                                                  (no-wildcards nil)
                                                  (no-partial-wildcards t)
                                                  (multi-label-wildcards nil)
                                                  (single-label-subdomain t))
  (do-x509-check certificate hostname +GEN-DNS+
    :always-check-subject always-check-subject
    :no-wildcards no-wildcards
    :no-partial-wildcards no-partial-wildcards
    :multi-label-wildcards multi-label-wildcards
    :single-label-subdomain single-label-subdomain))


(defun verify-emial (certificate email &key (always-check-subject t)))

(defun verify-ip (certificate ip &key (always-check-subject t)))

(defun verify-ip-asc (certificate ip &key (always-check-subject t)))
