#!/bin/bash

# exit on errors
set -ex

cd ~/github.com/qsslkey-p11
# echo "$PWD"

conda_prfx=/opt/mc3

source ${conda_prfx}/etc/profile.d/conda.sh

#conda_env=${conda_prfx}/envs/qgis3-deps
#build_dir=./build_profile_qgis3_qt5_mc3_forge_build_1010sdk

conda_env=${conda_prfx}/envs/qgis310-deps-openssl
build_dir=./build_profile_qgis310_qt512_openssl_mc3_forge_build_1010sdk

if [ "${CONDA_PREFIX}" != "${conda_env}" ]; then
  conda activate "${conda_env}"
fi

# SoftHSM
#pkcs11_mod=/usr/local/opt/softhsm/lib/softhsm/libsofthsm2.so
pkcs11_mod="${conda_env}/lib/softhsm/libsofthsm2.so"
token_str='pkcs11:token=SoftHSM-JillPerson;object=jill-key;type=private;pin-value=9900'
#token_str='pkcs11:token=SoftHSM-JillPerson;object=jill-key;type=private'

# OpenSC
# pkcs11_mod=/Library/OpenSC/lib/opensc-pkcs11.so
# token_str='pkcs11:token=Jill%20Person;object=CAC%20Cert%206;type=private;pin-value=9900'

# Just test with test PEM cert/key bundle
${build_dir}/qsslkey-p11-engine \
  "${conda_env}/lib/engines-1.1/libpkcs11.dylib"

#${build_dir}/qsslkey-p11-engine \
#  "${conda_env}/lib/engines-1.1/libpkcs11.dylib" \
#  $pkcs11_mod \
#  $token_str
