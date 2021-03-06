# QSslKey using PKCS#11

This example show how to use OpenSSL (http://www.openssl.org) along
with engine_pkcs11 (http://www.opensc-project.org/engine_pkcs11) to make a QSslSocket
use a private key and a certificate from an HSM (http://en.wikipedia.org/wiki/Hardware_Security_Module)
using PKCS#11 (http://en.wikipedia.org/wiki/PKCS11).

To test this example you'll need OpenSSL headers and libraries, a binary version of
engine_pkcs11 and a PKCS#11 module (.so or .dll that should comes with the device you're
using).

You will need a patched version of Qt available here:
https://qt.gitorious.org/~iksaif/qt/iksaifs-clone/commits/qssl

You'll also need a valid keypair present both on your HSM and on your disk (named cert.pem
and key.pem and put in a certs subdirectory).

Basically the example create an SSL server that will load cert.pem and key.pem as its
public and private keys. Then it'll create a client that'll load it's keys from the HSM
and connect to the server. If the client certificate matches the server certificate
then the test succeed.
