[![Build Status](https://github.com/cl-plus-ssl/cl-plus-ssl/actions/workflows/test.yml/badge.svg)](https://github.com/cl-plus-ssl/cl-plus-ssl/actions)

# CL+SSL

A Common Lisp interface to OpenSSL / LibreSSL.


## About

Distinguishing features: CL+SSL is portable code based on CFFI and gray
streams. It defines its own libssl BIO_METHOD, so that TLS I/O can be
written over portable Lisp streams instead of bypassing the streams and
giving OpenSSL a Unix file descriptors to send data over. (But the file
descriptor approach is still used if possible.)

License: MIT-style.


## Download

The library is available via [Quicklisp](http://www.quicklisp.org/).

The Git repository: <http://common-lisp.net/project/cl-plus-ssl/>.

Send bug reports to the GitHub issue trakcer. The old mailing list
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

Basically, after creating a TCP connection, we wrap the TCP socket stream
into an TLS encrypted stream using `cl+ssl:make-ssl-client-stream`,
or `cl+ssl:make-ssl-server-stream`. See how it's done in the
<examples/example.lisp> one. That is a self-contained file,
you can copy-paste it into your slime session and try the examples
as suggested in the comments at the top of the file.

## API

See the API section at the old project homepage: <http://common-lisp.net/project/cl-plus-ssl/>


## Portability

CL+SSL requires CFFI with callback support.

CL Test Grid results: <https://common-lisp.net/project/cl-test-grid/library/cl+ssl.html> 


## TODO

- session caching
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
