(in-package :cl+ssl.test)

(def-suite :cl+ssl.bio :in :cl+ssl
  :description "Bio interface test")

(in-suite :cl+ssl.bio)

(define-crypto-function ("BIO_write" bio-write)
  :int
  (bio :pointer)
  (text :string)
  (len :int))

(define-crypto-function ("BIO_read" bio-read)
  :int
  (bio :pointer)
  (text :pointer)
  (len :int))

(define-crypto-function ("BIO_gets" bio-gets)
  :int
  (bio :pointer)
  (text :pointer)
  (len :int))

(define-crypto-function ("BIO_puts" bio-puts)
  :int
  (bio :pointer)
  (text :string))


(test bio-read
      (is (equalp
	   (with-bio-input-from-string (bio "Hello")
	     (cffi:with-foreign-object (array :char 32)
	       (list
		(bio-read bio array 3)
		(cffi:foreign-string-to-lisp array)
		(bio-read bio array 32)
		(cffi:foreign-string-to-lisp array))))
	   ;; there is a bug somewhere, lol should be lo
	   '(3 "Hel" 2 "lo"))))

(test bio-gets
      (is (equalp
	   (with-bio-input-from-string (bio "Hello
bar")
	     (cffi:with-foreign-object (array :char 32)
	       (list
		(bio-gets bio array 32)
		(cffi:foreign-string-to-lisp array)
		(bio-gets bio array 32)
		(cffi:foreign-string-to-lisp array))))
	   '(5 "Hello" 3 "bar"))))

(test bio-write-puts
      (is (equalp
	   (with-bio-output-to-string (bio)
	     (bio-write bio  #1="Hello " (length #1#))
	     (bio-puts bio "Hi")
	     (bio-write bio  #2="Hallo" (length #2#)))
	   "Hello Hi
Hallo")))
