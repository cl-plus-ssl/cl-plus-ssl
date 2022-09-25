[![Build Status](https://github.com/cl-plus-ssl/cl-plus-ssl/actions/workflows/test.yml/badge.svg)](https://github.com/cl-plus-ssl/cl-plus-ssl/actions)

# CL+SSL

A Common Lisp interface to OpenSSL / LibreSSL.


## About

Distinguishing features: CL+SSL is portable code based on CFFI and gray
streams. It defines its own libssl BIO_METHOD, so that TLS I/O can be
written over portable Lisp streams instead of bypassing the streams and
giving OpenSSL a socket file descriptor to send data over. (But the file
descriptor approach is still used if possible.)

License: MIT-style.


## Download

The library is available via [Quicklisp](http://www.quicklisp.org/).

The Git repository: <http://common-lisp.net/project/cl-plus-ssl/>.

Send bug reports to the GitHub issue tracker. The old mailing list
[cl-plus-ssl-devel@common-lisp.net](mailto:cl-plus-ssl-devel@common-lisp.net)
is also still available
([list information](http://common-lisp.net/cgi-bin/mailman/listinfo/cl-plus-ssl-devel)). 


## OpenSSL / LibreSSL Installation Hints

### Unix-like

Usually OpenSSL / LibreSSL shared libraries are provided by your package manager
and very likely are already installed.

### Windows

<https://wiki.openssl.org/index.php/Binaries> lists several soruces of binary distributions. For example, <http://www.slproweb.com/products/Win32OpenSSL.html> (slproweb.com is a 3rd party; if you have questions about the OpenSSL installer they provide, please ask in the mailing list specified on the linked page).

If you chose to install the DLLs into the OpenSSL installation's "bin" directory (recommended), then be sure to add the bin directory to your PATH environment variable and restart your session. e.g. "C:\Program Files\OpenSSL-Win64\bin"


## Usage

Basically, after TCP connection is created, we wrap the TCP socket stream
into a TLS encrypted stream using `cl+ssl:make-ssl-client-stream`,
or `cl+ssl:make-ssl-server-stream`. See how it's done in the
[examples/example.lisp](examples/example.lisp). That's a
self-contained file, you can load it or copy-paste into your
Slime session and try the examples as suggested in the comments at the
top of the file.

For more comfortable use learn some of OpenSSL API. In particular
that SSL object represents a TLS session, CTX object is a
context multiple SSL objects can derive from thus sharing
common parameters. BIO is a stream-like input/ouput abstraction
OpenSSL uses for actual data transfer.

Knowing OpenSSL will also allow for more flexibility and control,
as cl+ssl high-level functions do not cover all possible approaches.

### Lisp BIO or Socket BIO.

OpenSSL comes with several BIO types predefined, like file BIO,
socket BIO, memory BIO, etc. Also OpenSSL API allows user to
create custom BIO methods by providing a number of callbacks.

cl+ssl uses either socket BIO, or a custom BIO that implements
all input / output with Lisp functions like `cl:write-byte`,
`cl:read-byte`.

When a Lisp stream is passed to `cl+ssl:make-ssl-client-stream`
or `cl+ssl:make-ssl-server-stream`, the choice of BIO is made
based on the `:unwrap-stream-p` parameter.

If `:unwrap-stream-p` is true, a socket file descriptor is extracted
from the Lisp stream and passed to OpenSSL using the `SSL_set_fd`
OpenSSL function.

If `:unwrap-stream-p` is false, a Lisp BIO is created and
passed to OpenSSL with the `SSL_set_bio` OpenSSL funcion.

The default value of `:unwrap-stream-p` is special variable
`cl+ssl:*default-unwrap-stream-p*` which is initialized to `t`,
meaning socket BIO is used by default.

This allows to dynamically change the mode of operation of the
code that omits the `:unwrap-stream-p` parameter.

For the `test-https-client` function from the example.lisp:

```common-lisp

;; use socket BIO
(let ((cl+ssl:*default-unwrap-stream-p* t))
  (tls-example::test-https-client "www.google.com"))

;; use Lisp BIO
(let ((cl+ssl:*default-unwrap-stream-p* nil))
  (tls-example::test-https-client "www.google.com"))

```

If `cl+ssl:make-ssl-*-stream` functions receive
a file descriptor instead of a Lisp stream,
they unconditionally use socket BIO.

### Customize Shared Libraries Location

By default cl+ssl searches for OpenSSL shared libraries
in platform-dependent default locations.

To explicitly specify what to load use cl+ssl/config
module before loading cl+ssl:

```common-lisp
(ql:quickload :cl+ssl/config)
(cl+ssl/config:define-libssl-path "/opt/local/lib/libssl.dylib")
(cl+ssl/config:define-libcrypto-path "/opt/local/lib/libcrypto.dylib")
(ql:quickload :cl+ssl)

```
Note, the `path` parameter of those two macros is not evaluated.

### Timeouts and Deadlines

TODO

### Saved Lisp Image

If you save your application as Lisp image, call `(cl+ssl:reload)`
after loading that image.

This should work fine if the location and version
of the OpenSSL shared libraries have *not* changed.
If they have changed, you may get errors anyway,
as users report: https://github.com/cl-plus-ssl/cl-plus-ssl/issues/167


## API

See the API section at the old project homepage:
<http://common-lisp.net/project/cl-plus-ssl/>

Note, the docstrings are sometimes incomplete - if a function was not
initially documented, and contributor introduces new parameter,
he would often document only that new parameter.

## Portability

CL+SSL requires CFFI with callback support.

CL Test Grid results: <https://common-lisp.net/project/cl-test-grid/library/cl+ssl.html> 


## TODO

- session caching (what about it?)
- The FFI code for all platforms except clisp needs to be rewritten. (update 2017-07-05: does it? why?)


## History

This library is a fork of [SSL-CMUCL](http://www.cliki.net/SSL-CMUCL).
The original SSL-CMUCL source code was written by Eric Marsden and
includes contributions by Jochen Schmidt.

Jochen Schmidt also has his own portable CL-SSL bindings (Gray streams
based), [available]( https://sourceforge.net/p/portableaserve/git/ci/master/tree/acl-compat/)
as a part of the acl-compat portability layer of his
[http://portableaserve.sourceforge.net/](http://portableaserve.sourceforge.net/).

Development into CL+SSL was done by David Lichteblau. After that many
peeple contributed patches, as can be seenn in the git history.


## News (Old, not really maintained now)

2017-07-03

- Hostname verification added, thanks to Ilya Khaprov. Default mode for make-ssl-client-stream is to verify the connection. New keywrd argument verify is added to make-ssl-client-stream with the same possible values as Drakma uses for http request verification.

201?-??-??

- See commits.

2011-05-22

- Added new public function RANDOM-BYTES.

2011-05-22

- The source code repository is moved to Git.

2011-03-25

- OpenSSL libraries names for OpenBSD, thanks to Thomas de Grivel.

2010-05-26

- Fixed two bugs in LISTEN, thanks to Ron Garret.

2009-09-17

- libssl loading on FreeBSD 7.2 fixed, thanks to Stian Sletner.

2008-xx-yy

- Support for I/O deadlines (Clozure CL and SBCL).
- Support for encrypted keys, thanks to Vsevolod Dyomkin.
- Chained certificates support, thanks to Juhani Ränkimies.
- More secure initialization of OpenSSL random number generator.
- Minor CLISP-specific fixes.

2007-xx-yy

- Fixed windows support, thanks to Matthew Kennedy and Anton Vodonosov.

2007-07-07

- Improved CLISP support, thanks to [Pixel // pinterface](http://web.kepibu.org/code/lisp/cl+ssl/), as well as client certificate support.
- Re-introduced support for direct access to file descriptors as an optimization. New function stream-fd. New keyword argument close-callback.

2007-01-16: CL+SSL is now available under an MIT-style license.
