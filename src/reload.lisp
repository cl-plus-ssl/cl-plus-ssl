;;;; -*- Mode: LISP; Syntax: COMMON-LISP; indent-tabs-mode: nil; coding: utf-8; show-trailing-whitespace: t -*-
;;;
;;; Copyright (C) 2001, 2003  Eric Marsden
;;; Copyright (C) 2005  David Lichteblau
;;; "the conditions and ENSURE-SSL-FUNCALL are by Jochen Schmidt."
;;;
;;; See LICENSE for details.

;;; We do this in an extra file so that it happens
;;;   - after the asd file has been loaded, so that users can
;;;     customize *libssl-pathname* between loading the asd and LOAD-OPing
;;;     the actual sources
;;;   - before ssl.lisp is loaded, which needs the library at compilation
;;;     time on some implemenations
;;;   - but not every time ffi.lisp is re-loaded as would happen if we
;;;     put this directly into ffi.lisp

#+xcvb (module (:depends-on ("package")))

(in-package :cl+ssl)



;; Windows builds have been naming librypto and libssl DLLs in several different ways:
;;
;; - libeay32.dll, libssl32.dll
;; - libeay32.dll, ssleay32.dll
;;
;; Note, the above names were used both for 32 and 64 -bit versions.
;;
;; - libcrypto-1_1-x64.dll, libssl-1_1-x64.dll
;;
;; The above are used for 64-bit only.
;;
;; - libcrypto-1_1.dll, libssl-1_1.dll
;;
;; These are 32-bit only.

(unless *libcrypto-override*
  (cffi:define-foreign-library libcrypto
    (:windows (:or #+(and windows x86-64) "libcrypto-1_1-x64.dll"
                   #+(and windows x86) "libcrypto-1_1.dll"
                   "libeay32.dll"))
    (:openbsd "libcrypto.so")
    (:darwin (:or "/opt/local/lib/libcrypto.dylib"                ;; MacPorts
                  "/sw/lib/libcrypto.dylib"                       ;; Fink
                  "/usr/local/opt/openssl/lib/libcrypto.dylib"    ;; Homebrew
                  "/opt/homebrew/opt/openssl/lib/libcrypto.dylib" ;; Homebrew Arm64
                  "/usr/local/lib/libcrypto.dylib" ;; personalized install

                  ;; System-provided libraries. These must be loaded with an explicit
                  ;; API version, or else the process will crash (that was just a warning
                  ;; starging frmo maxOS > 10.15, and finally macOS >= 11 crashes the process
                  ;; with a fatal error)
                  ;;
                  ;; Please note that in macOS >= 11.0, these paths may not exist in the
                  ;; file system anymore, but trying to load them via dlopen will work. This
                  ;; is because macOS ships all system-provided libraries as a single
                  ;; dyld_shared_cache bundle.
                  "/usr/lib/libcrypto.44.dylib"
                  "/usr/lib/libcrypto.42.dylib"
                  "/usr/lib/libcrypto.41.dylib"
                  "/usr/lib/libcrypto.35.dylib"

                  ;; The default old system libcrypto, versionless file name,
                  ;; which may have insufficient crypto and can cause
                  ;; process crash on macOS >= 11. Currently we
                  ;; are protected from the crash by the presense of
                  ;; the versioned paths above, but in fiew years,
                  ;; after those exacty versioned paths are not available,
                  ;; the crash may re-appear. So eventially we will
                  ;; need to delete the unversioned paths.
                  ;; Keeping them for a while for compatibility.
                  ;; See https://github.com/cl-plus-ssl/cl-plus-ssl/pull/115
                  "libcrypto.dylib"
                  "/usr/lib/libcrypto.dylib"))
    ((and :unix (not :cygwin)) (:or "libcrypto.so.1.1"
                                    "libcrypto.so.1.0.0"
                                    "libcrypto.so"))
    (:cygwin (:or "cygcrypto-1.1.dll" "cygcrypto-1.0.0.dll"))))

(unless *libssl-override*
  (cffi:define-foreign-library libssl
    (:windows (:or #+(and windows x86-64) "libssl-1_1-x64.dll"
                   #+(and windows x86) "libssl-1_1.dll"
                   "libssl32.dll"
                   "ssleay32.dll"))
    ;; The default OS-X libssl seems have had insufficient crypto algos
    ;; (missing TLSv1_[1,2]_XXX methods,
    ;; see https://github.com/cl-plus-ssl/cl-plus-ssl/issues/56)
    ;; so first try to load possible custom installations of libssl
    (:darwin (:or "/opt/local/lib/libssl.dylib"                ;; MacPorts
                  "/sw/lib/libssl.dylib"                       ;; Fink
                  "/usr/local/opt/openssl/lib/libssl.dylib"    ;; Homebrew
                  "/opt/homebrew/opt/openssl/lib/libssl.dylib" ;; Homebrew Arm64
                  "/usr/local/lib/libssl.dylib" ;; personalized install
                  "libssl.dylib" ;; default system libssl, which may have insufficient crypto
                  "/usr/lib/libssl.dylib"))
    (:solaris (:or "/lib/64/libssl.so"
                   "libssl.so.0.9.8" "libssl.so" "libssl.so.4"))
    ;; Unlike some other systems, OpenBSD linker,
    ;; when passed library name without versions at the end,
    ;; will locate the library with highest macro.minor version,
    ;; so we can just use just "libssl.so".
    ;; More info at https://github.com/cl-plus-ssl/cl-plus-ssl/pull/2.
    (:openbsd "libssl.so")
    ((and :unix (not :cygwin)) (:or "libssl.so.1.1"
                                    "libssl.so.1.0.2m"
                                    "libssl.so.1.0.2k"
                                    "libssl.so.1.0.2"
                                    "libssl.so.1.0.1l"
                                    "libssl.so.1.0.1j"
                                    "libssl.so.1.0.1f"
                                    "libssl.so.1.0.1e"
                                    "libssl.so.1.0.1"
                                    "libssl.so.1.0.0q"
                                    "libssl.so.1.0.0"
                                    "libssl.so.0.9.8ze"
                                    "libssl.so.0.9.8"
                                    "libssl.so.10"
                                    "libssl.so.4"
                                    "libssl.so"))
    (:cygwin (:or "cygssl-1.1.dll" "cygssl-1.0.0.dll"))
    (t (:default "libssl3"))))

(unless (member :cl+ssl-foreign-libs-already-loaded
                *features*)
  (cffi:use-foreign-library libcrypto)
  (cffi:use-foreign-library libssl))
