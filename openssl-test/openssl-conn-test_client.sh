#!/bin/bash

# OpenSSL test client for PKI connections

# LS 2019-12-13

# Tested against OpenSSL 1.1.1d  10 Sep 2019
# Tested against OpenSSL 1.1.1f  04 Apr 2020


# Stand up test client

set -e

# Set up planet test certs for server and client authentication validation

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")"; pwd -P)
TEST_CERTS="$(dirname "${SCRIPT_DIR}")/certs"

# Ensure whatever openssl needs launched is found first on PATH
# (here for conda-forge's openssl)
source /opt/mc3/etc/profile.d/conda.sh

conda_env=/opt/mc3/envs/qgis310-deps-openssl

if [ "${CONDA_PREFIX}" != "${conda_env}" ]; then
  conda activate "${conda_env}"
fi

# use `openssl s_client --help` to verify specific options
# options in order of --help output

# Basic PKI connection with test PEM files
#${conda_env}/bin/openssl s_client -connect openssl.planet.local:4443 \
#  -verify 5 \
#  -verify_return_error \
#  -CAfile ${TEST_CERTS}/ca-chains.pem \
#  -showcerts \
#  -cert ${TEST_CERTS}/client-cert.pem \
#  -key ${TEST_CERTS}/client-key.pem \
#  -state \
#  -status \
#  -tls1_2

#exit 0


export OPENSSL_CONF="${SCRIPT_DIR}/test-client_conda-openssl.cnf"

# Note: successful connections will end with prompt for an HTTP command, e.g.
# GET /
# if using -WWW on the test server, request:
# GET/test.html (returns contents of test.html)
${conda_env}/bin/openssl s_client -connect openssl.planet.local:4443 \
  -verify 5 \
  -verify_return_error \
  -engine pkcs11 \
  -CAfile ${TEST_CERTS}/ca-chains.pem \
  -showcerts \
  -cert ${TEST_CERTS}/client-cert.pem \
  -keyform ENGINE \
  -key 'pkcs11:token=SoftHSM-JillPerson;object=jill-key;type=private;pin-value=9900' \
  -state \
  -status \
  -tls1_2

#  -key ${TEST_CERTS}/client-key.pem \
#  -key "pkcs11:token=Jill%20Person;object=CAC%20Cert%206;type=private" \
#  -key 'pkcs11:token=SoftHSM-JillPerson;object=jill-key;type=private;pin-value=9900' \
#  -cert 'pkcs11:token=Jill%20Person;object=CAC%20Cert%206;type=cert;pin-value=9900' \
#  -cert 0:0006 \

#  -key slot_0-id_0006 \
#  -build_chain \
#  -chainCAfile ${TEST_CERTS}/client-ca.pem \
#  -CAfile ${TEST_CERTS}/ca-chains.pem \
#  -CApath ${TEST_CERTS} \
#  -verifyCAfile ${TEST_CERTS}/ca-chains.pem \


# For macOS conda-forge OpenSSL
#
# $ openssl version
# OpenSSL 1.1.1d  10 Sep 2019
#
# $ openssl s_client --help
#  Usage: s_client [options]
#  Valid options are:
#   -help                      Display this summary
#   -host val                  Use -connect instead
#   -port +int                 Use -connect instead
#   -connect val               TCP/IP where to connect (default is :4433)
#   -bind val                  bind local address for connection
#   -proxy val                 Connect to via specified proxy to the real server
#   -unix val                  Connect over the specified Unix-domain socket
#   -4                         Use IPv4 only
#   -6                         Use IPv6 only
#   -verify +int               Turn on peer certificate verification
#   -cert infile               Certificate file to use, PEM format assumed
#   -certform PEM|DER          Certificate format (PEM or DER) PEM default
#   -nameopt val               Various certificate name options
#   -key val                   Private key file to use, if not in -cert file
#   -keyform PEM|DER|ENGINE    Key format (PEM, DER or engine) PEM default
#   -pass val                  Private key file pass phrase source
#   -CApath dir                PEM format directory of CA's
#   -CAfile infile             PEM format file of CA's
#   -no-CAfile                 Do not load the default certificates file
#   -no-CApath                 Do not load certificates from the default certificates directory
#   -requestCAfile infile      PEM format file of CA names to send to the server
#   -dane_tlsa_domain val      DANE TLSA base domain
#   -dane_tlsa_rrdata val      DANE TLSA rrdata presentation form
#   -dane_ee_no_namechecks     Disable name checks when matching DANE-EE(3) TLSA records
#   -reconnect                 Drop and re-make the connection with the same Session-ID
#   -showcerts                 Show all certificates sent by the server
#   -debug                     Extra output
#   -msg                       Show protocol messages
#   -msgfile outfile           File to send output of -msg or -trace, instead of stdout
#   -nbio_test                 More ssl protocol testing
#   -state                     Print the ssl states
#   -crlf                      Convert LF from terminal into CRLF
#   -quiet                     No s_client output
#   -ign_eof                   Ignore input eof (default when -quiet)
#   -no_ign_eof                Don't ignore input eof
#   -starttls val              Use the appropriate STARTTLS command before starting TLS
#   -xmpphost val              Alias of -name option for "-starttls xmpp[-server]"
#   -rand val                  Load the file(s) into the random number generator
#   -writerand outfile         Write random data to the specified file
#   -sess_out outfile          File to write SSL session to
#   -sess_in infile            File to read SSL session from
#   -use_srtp val              Offer SRTP key management with a colon-separated profile list
#   -keymatexport val          Export keying material using label
#   -keymatexportlen +int      Export len bytes of keying material (default 20)
#   -maxfraglen +int           Enable Maximum Fragment Length Negotiation (len values: 512, 1024, 2048 and 4096)
#   -fallback_scsv             Send the fallback SCSV
#   -name val                  Hostname to use for "-starttls lmtp", "-starttls smtp" or "-starttls xmpp[-server]"
#   -CRL infile                CRL file to use
#   -crl_download              Download CRL from distribution points
#   -CRLform PEM|DER           CRL format (PEM or DER) PEM is default
#   -verify_return_error       Close connection on verification error
#   -verify_quiet              Restrict verify output to errors
#   -brief                     Restrict output to brief summary of connection parameters
#   -prexit                    Print session information when the program exits
#   -security_debug            Enable security debug messages
#   -security_debug_verbose    Output more security debug output
#   -cert_chain infile         Certificate chain file (in PEM format)
#   -chainCApath dir           Use dir as certificate store path to build CA certificate chain
#   -verifyCApath dir          Use dir as certificate store path to verify CA certificate
#   -build_chain               Build certificate chain
#   -chainCAfile infile        CA file for certificate chain (PEM format)
#   -verifyCAfile infile       CA file for certificate verification (PEM format)
#   -nocommands                Do not use interactive command letters
#   -servername val            Set TLS extension servername (SNI) in ClientHello (default)
#   -noservername              Do not send the server name (SNI) extension in the ClientHello
#   -tlsextdebug               Hex dump of all TLS extensions received
#   -status                    Request certificate status from server
#   -serverinfo val            types  Send empty ClientHello extensions (comma-separated numbers)
#   -alpn val                  Enable ALPN extension, considering named protocols supported (comma-separated list)
#   -async                     Support asynchronous operation
#   -ssl_config val            Use specified configuration file
#   -max_send_frag +int        Maximum Size of send frames
#   -split_send_frag +int      Size used to split data for encrypt pipelines
#   -max_pipelines +int        Maximum number of encrypt/decrypt pipelines to be used
#   -read_buf +int             Default read buffer size to be used for connections
#   -no_ssl3                   Just disable SSLv3
#   -no_tls1                   Just disable TLSv1
#   -no_tls1_1                 Just disable TLSv1.1
#   -no_tls1_2                 Just disable TLSv1.2
#   -no_tls1_3                 Just disable TLSv1.3
#   -bugs                      Turn on SSL bug compatibility
#   -no_comp                   Disable SSL/TLS compression (default)
#   -comp                      Use SSL/TLS-level compression
#   -no_ticket                 Disable use of TLS session tickets
#   -serverpref                Use server's cipher preferences
#   -legacy_renegotiation      Enable use of legacy renegotiation (dangerous)
#   -no_renegotiation          Disable all renegotiation.
#   -legacy_server_connect     Allow initial connection to servers that don't support RI
#   -no_resumption_on_reneg    Disallow session resumption on renegotiation
#   -no_legacy_server_connect  Disallow initial connection to servers that don't support RI
#   -allow_no_dhe_kex          In TLSv1.3 allow non-(ec)dhe based key exchange on resumption
#   -prioritize_chacha         Prioritize ChaCha ciphers when preferred by clients
#   -strict                    Enforce strict certificate checks as per TLS standard
#   -sigalgs val               Signature algorithms to support (colon-separated list)
#   -client_sigalgs val        Signature algorithms to support for client certificate authentication (colon-separated list)
#   -groups val                Groups to advertise (colon-separated list)
#   -curves val                Groups to advertise (colon-separated list)
#   -named_curve val           Elliptic curve used for ECDHE (server-side only)
#   -cipher val                Specify TLSv1.2 and below cipher list to be used
#   -ciphersuites val          Specify TLSv1.3 ciphersuites to be used
#   -min_protocol val          Specify the minimum protocol version to be used
#   -max_protocol val          Specify the maximum protocol version to be used
#   -record_padding val        Block size to pad TLS 1.3 records to.
#   -debug_broken_protocol     Perform all sorts of protocol violations for testing purposes
#   -no_middlebox              Disable TLSv1.3 middlebox compat mode
#   -policy val                adds policy to the acceptable policy set
#   -purpose val               certificate chain purpose
#   -verify_name val           verification policy name
#   -verify_depth int          chain depth limit
#   -auth_level int            chain authentication security level
#   -attime intmax             verification epoch time
#   -verify_hostname val       expected peer hostname
#   -verify_email val          expected peer email
#   -verify_ip val             expected peer IP address
#   -ignore_critical           permit unhandled critical extensions
#   -issuer_checks             (deprecated)
#   -crl_check                 check leaf certificate revocation
#   -crl_check_all             check full chain revocation
#   -policy_check              perform rfc5280 policy checks
#   -explicit_policy           set policy variable require-explicit-policy
#   -inhibit_any               set policy variable inhibit-any-policy
#   -inhibit_map               set policy variable inhibit-policy-mapping
#   -x509_strict               disable certificate compatibility work-arounds
#   -extended_crl              enable extended CRL features
#   -use_deltas                use delta CRLs
#   -policy_print              print policy processing diagnostics
#   -check_ss_sig              check root CA self-signatures
#   -trusted_first             search trust store first (default)
#   -suiteB_128_only           Suite B 128-bit-only mode
#   -suiteB_128                Suite B 128-bit mode allowing 192-bit algorithms
#   -suiteB_192                Suite B 192-bit-only mode
#   -partial_chain             accept chains anchored by intermediate trust-store CAs
#   -no_alt_chains             (deprecated)
#   -no_check_time             ignore certificate validity time
#   -allow_proxy_certs         allow the use of proxy certificates
#   -xkey infile               key for Extended certificates
#   -xcert infile              cert for Extended certificates
#   -xchain infile             chain for Extended certificates
#   -xchain_build              build certificate chain for the extended certificates
#   -xcertform PEM|DER         format of Extended certificate (PEM or DER) PEM default
#   -xkeyform PEM|DER          format of Extended certificate's key (PEM or DER) PEM default
#   -tls1                      Just use TLSv1
#   -tls1_1                    Just use TLSv1.1
#   -tls1_2                    Just use TLSv1.2
#   -tls1_3                    Just use TLSv1.3
#   -dtls                      Use any version of DTLS
#   -timeout                   Enable send/receive timeout on DTLS connections
#   -mtu +int                  Set the link layer MTU
#   -dtls1                     Just use DTLSv1
#   -dtls1_2                   Just use DTLSv1.2
#   -nbio                      Use non-blocking IO
#   -psk_identity val          PSK identity
#   -psk val                   PSK in hex (without 0x)
#   -psk_session infile        File to read PSK SSL session from
#   -srpuser val               SRP authentication for 'user'
#   -srppass val               Password for 'user'
#   -srp_lateuser              SRP username into second ClientHello message
#   -srp_moregroups            Tolerate other than the known g N values.
#   -srp_strength +int         Minimal length in bits for N
#   -nextprotoneg val          Enable NPN extension, considering named protocols supported (comma-separated list)
#   -engine val                Use engine, possibly a hardware device
#   -ssl_client_engine val     Specify engine to be used for client certificate operations
#   -ct                        Request and parse SCTs (also enables OCSP stapling)
#   -noct                      Do not request or parse SCTs (default)
#   -ctlogfile infile          CT log list CONF file
#   -keylogfile outfile        Write TLS secrets to file
#   -early_data infile         File to send as early data
#   -enable_pha                Enable post-handshake-authentication
