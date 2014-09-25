;;; Copyright (C) 2014  Ilya Khaprov https://github.com/deadtrickster
;;;
;;; See LICENSE for details.

#+xcvb
(module
 (:depends-on ("package" "conditions" "ffi")))

(eval-when (:compile-toplevel)
  (declaim
   (optimize (speed 3) (space 1) (safety 1) (debug 0) (compilation-speed 0))))


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

(declaim (inline set-flags add-flag remove-flag flag-set-p))
(defun set-flags (&rest flags)
  (apply #'logior flags))

(defun add-flag (flags flag)
  (declare (type fixnum flags flag))
  (logior flags flag))

(defun remove-flag (flags flag)  
  (declare (type fixnum flags flag))
  (logand flags (lognot flag)))

(defun flag-set-p (flags flag &optional match)  
  (declare (type fixnum flags flag))
  (let ((r (logand flags flag)))
    (if (> r 0)
        (if match
            (= r flag)
            t)
        nil)))

;; (defun remove-trailing-dot (str)
;;   (declare (type string str))
;;   (if (eql (elt str (1- (length str))) #\.)
;;       (subseq str 0 (- (length str) 2))
;;       str))

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

(defun try-match-using-wildcards (pattern subject flags)
  (declare (type string pattern subject)
           (type fixnum flags))
  ;; wildcard must match at least one character
  (when (> (length pattern) (length subject))
    (return-from try-match-using-wildcards nil))

  (let ((pattern-w-pos (position #\* pattern))
        (pattern-leftmost-label-end))
    (unless pattern-w-pos
      (return-from try-match-using-wildcards nil))

    ;; only one star
    (when (position #* pattern :start pattern-w-pos)
      (return-from try-match-using-wildcards (values nil :not-single-star)))

    ;; check if pattern has at least two dots after star
    (setq pattern-leftmost-label-end (position #\. pattern))
    (when (or (null pattern-leftmost-label-end)
              (null (position #\. pattern :start (1+ pattern-leftmost-label-end))))
      (return-from try-match-using-wildcards (values nil :too-few-dots-after-star)))

    ;; check no labels(dots) behind star
    (when (> pattern-w-pos pattern-leftmost-label-end)
      (return-from try-match-using-wildcards (values nil :star-not-in-leftmost)))

    ;;check star is not part of A-label label, what about U-labels though?
    (when (search "xn--" pattern :test #'equal :end2 pattern-leftmost-label-end)
      (return-from try-match-using-wildcards (values nil :star-in-a-label)))

    (let* ((pattern-length-after-star (- (length pattern) pattern-w-pos 1 #|not include star|#))
           (hostname-position-after-star (- (length subject) pattern-length-after-star)))

      (unless (flag-set-p flags +x509-check-flag-multi-label-wildcards+)
        ;; do not allow *.example.com match bar.foo.example.com
        (when (position #\. subject :end hostname-position-after-star)
          (return-from try-match-using-wildcards (values nil :multilable-match))))

      (when (flag-set-p flags +x509-check-flag-no-partial-wildcards+)
        (unless (eql (aref pattern (1+ pattern-w-pos)) #\.)
          (return-from try-match-using-wildcards (values nil :maybe-partial-match)))
        (unless (eql pattern-w-pos 0)
          (return-from try-match-using-wildcards (values nil :maybe-partial-match))))

      ;; partially match part after star
      (if (string-equal subject pattern :start1  hostname-position-after-star :start2 (1+ pattern-w-pos))
          (if (= 0 pattern-w-pos)
              t
              ;; match before star part now
              (if (string-equal subject pattern :end1 pattern-w-pos :end2 pattern-w-pos)
                  t
                  (values nil :no-match-before-star)))
          (values nil :no-match-after-star)))))

(defun skip-prefix (pattern subject flags)
  (declare (type string pattern subject)
           (type fixnum flags))
  (unless (flag-set-p flags +_x509-check-flag-dot-subdomains+)
    (return-from skip-prefix 0))
  #|
  * If subject starts with a leading '.' followed by more octets, and
  * pattern is longer, compare just an equal-length suffix with the
  * full subject (starting at the '.')
  *|#

  (let ((pattern-length (length pattern)))
    (unless (> pattern-length (length subject))
      (return-from skip-prefix 0))
    (do ((i 0 (1+ i)))
        ((or (<= pattern-length (length subject)) (= pattern-length 0)) i)
      (when (and (eql (aref pattern i) #\.)
                 (flag-set-p flags +x509-check-flag-single-label-subdomains+))
        (return i))
      (decf pattern-length))))

(defun just-equal (pattern subject flags)
  (declare (type string pattern subject))
  (declare (ignore flags))
  (equal pattern subject))

(defun equal-case (pattern subject flags)
  (declare (type string pattern subject)
           (type fixnum flags))
  (let ((pattern-start (skip-prefix pattern subject flags)))
    (string= pattern subject :start1 pattern-start)))

(defun equal-nocase (pattern subject flags)
  (declare (type string pattern subject)
           (type fixnum flags))
  (let ((pattern-start (skip-prefix pattern subject flags)))
    (string-equal pattern subject :start1 pattern-start)))

(defun equal-wildcard (pattern subject flags)
  (declare (type string pattern subject)
           (type fixnum flags))
  (if (equal-nocase subject pattern flags)
      t
      (try-match-using-wildcards pattern subject flags)))

(defun equal-email (pattern subject flags)
  (declare (type string pattern subject)
           (type fixnum flags))
  (declare (ignore flags))
  (let* ((length (length pattern))
         (i length))
    (when (/= length (length subject))
      (return-from equal-email nil))

    #|We search backwards for the '@' character, so that we do
    not have to deal with quoted local-parts.  The domain part
    is compared in a case-insensitive manner.|#
    (do ()
        ((<= i 0))
      (decf i)
      (when (or (eql (aref pattern i) #\@) (eql (aref subject i) #\@))
        (return)
        (unless (string-equal pattern subject :start1 i :start2 i)
          (return-from equal-email nil))))
    (string= pattern subject :end1 i :end2 i)))

(defun try-match-pattern (pattern subject equality-function flags)
  (declare (type string subject)
           (type fixnum flags)
           (type (function (string string fixnum) boolean) equality-function))
  (let ((pattern-string (try-get-asn1-string-data pattern)))
    (unless pattern-string
      (return-from try-match-pattern (values nil :invalid-pattern-string)))
    (if (funcall equality-function pattern-string subject flags)
        (values t pattern-string))))

(defun try-match (pattern subject asn1-string-type equality-function flags)
  (declare (type cffi:foreign-pointer pattern)
           (type string subject)
           (type fixnum asn1-string-type flags)
           (type (function (string string fixnum) boolean) equality-function))
  (when (or (cffi:null-pointer-p (asn1-string-data pattern))
            (= 0 (asn1-string-length pattern)))
    (return-from try-match (values nil :invalid-pattern-structure)))

  (if (> asn1-string-type 0)
      (cond
        ((/= (asn1-string-type pattern) asn1-string-type)
         (return-from try-match (values nil :wrong-pattern-type)))
        ((= (asn1-string-type pattern) +V-ASN1-IASTRING+)
         (try-match-pattern pattern subject equality-function flags))
        (t (try-match-pattern pattern subject #'just-equal flags)))
      (try-match-pattern pattern subject equality-function flags)))

(defconstant +NID-commonName+   13)
(defconstant +NID-pkcs9-emailAddress+   48)

(defun do-x509-check (certificate subject subject-type flags)
  (declare (type cffi:foreign-pointer certificate)
           (type string subject)
           (type fixnum flags subject-type))
  (setq flags (remove-flag flags +_X509-CHECK-FLAG-DOT-SUBDOMAINS+))
  (let (common-name-id asn1-string-type equality-function)
    (cond
      ((eql subject-type +GEN-EMAIL+)
       (setf common-name-id +NID-pkcs9-emailAddress+
             asn1-string-type +V-ASN1-IASTRING+
             equality-function #'equal-email))
      ((eql subject-type +GEN-DNS+)
       (setf common-name-id +NID-commonName+
             asn1-string-type +V-ASN1-IASTRING+
             equality-function (if (flag-set-p flags +x509-check-flag-no-wildcards+)
                                   #'equal-nocase
                                   #'equal-wildcard))
       (if (and (> (length subject) 1)
                (eql #\. (aref subject 0)))
           (setf flags (add-flag flags +_X509-CHECK-FLAG-DOT-SUBDOMAINS+))))
      (t (setf asn1-string-type +V-ASN1-OCTET-STRING+
               equality-function #'equal-case
               common-name-id 0)))

    ;; first try match altname if any
    (let ((altnames (x509-get-ext-d2i certificate 85 #|NID_subject_alt_name|# (cffi:null-pointer) (cffi:null-pointer))))
      (if (not (cffi:null-pointer-p altnames))
          (unwind-protect
               (progn (let ((altnames-count (sk-general-name-num altnames)))
                        (do ((i 0 (1+ i)))
                            ((>= i altnames-count))
                          (let* ((alt-name (sk-general-name-value altnames i)))
                            (cffi:with-foreign-slots ((type data) alt-name (:struct general_name))
                              (when (= type subject-type)
                                (multiple-value-bind (result reason)
                                    (try-match data subject asn1-string-type equality-function flags)
                                  (if result
                                      (return-from do-x509-check (values t reason)))))))))
                      (when (and (not common-name-id)
                                 (not (flag-set-p flags +X509-check-flag-always-check-subject+)))
                        (return-from do-x509-check (values nil :no-alt-name-match))))
            (general-names-free altnames)
            )))
    ;; no alt names or always check subject
    (let ((i -1)
          (subject-name (x509-get-subject-name certificate)))
      (loop
        (setf i (x509-name-get-index-by-nid subject-name common-name-id i))
        (when (< i 0)
          (return (values nil :no-common-name-match))
          (let* ((entry (x509-name-get-entry subject-name i)))
            (multiple-value-bind (result reason)
                (try-match (x509-name-entry-get-data entry) subject -1 equality-function)
              (if result
                  (return-from do-x509-check (values result reason))))))))))


(defun verify-hostname (certificate hostname &optional (flags (set-flags +X509-CHECK-FLAG-ALWAYS-CHECK-SUBJECT+
                                                                         +X509-CHECK-FLAG-NO-PARTIAL-WILDCARDS+
                                                                         +X509-CHECK-FLAG-SINGLE-LABEL-SUBDOMAINS+)))
  (do-x509-check certificate hostname +GEN-DNS+ flags))


(defun verify-emial (certificate email &optional (flags +X509-CHECK-FLAG-ALWAYS-CHECK-SUBJECT+))
  (do-x509-check certificate email +GEN-EMAIL+ flags))

(defun verify-ip (certificate ip &optional (flags +X509-CHECK-FLAG-ALWAYS-CHECK-SUBJECT+))
  (do-x509-check certificate ip +GEN-IPADD+ flags))

(defun verify-ip-asc (certificate ip &optional (flags +X509-CHECK-FLAG-ALWAYS-CHECK-SUBJECT+))
  (error "Not implemented"))
