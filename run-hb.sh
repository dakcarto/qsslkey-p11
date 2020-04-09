#!/bin/bash

# exit on errors
set -e

cd ~/github.com/qsslkey-p11
# echo "$PWD"


build_dir=./build_profile_qt5_homebrew

# SoftHSM
pkcs11_mod=/usr/local/opt/softhsm/lib/softhsm/libsofthsm2.so
#token_str='pkcs11:token=SoftHSM-JillPerson;object=jill-key;type=private;pin-value=9900'
token_str='pkcs11:token=SoftHSM-JillPerson;object=jill-key;type=private'
# OpenSC
#pkcs11_lib=/Library/OpenSC/lib/opensc-pkcs11.so
#token_str='pkcs11:token=Jill%20Person;object=CAC%20Cert%206;type=private;pin-value=9900'

${build_dir}/qsslkey-p11 \
  /usr/local/opt/libp11/lib/engines-1.1/libpkcs11.dylib \
  $pkcs11_mod \
  $token_str
