TEMPLATE = app
TARGET = qsslkey-p11
DEPENDPATH += .
INCLUDEPATH += .
QT += widgets network
CONFIG += console
CONFIG += debug_and_release

# OpenSSL
win32 {
  INCLUDEPATH += -I D:/dev/commonit/openssl/include/
  LIBS += -LD:/dev/commonit/openssl/lib/VC -llibeay32MD -lssleay32MD
}
macx {
  CONFIG -= app_bundle
#  INCLUDEPATH += -I /usr/local/opt/openssl@1.1/include
#  LIBS += -L /usr/local/opt/openssl@1.1/lib -lcrypto -lssl
  INCLUDEPATH += -I /opt/mc3/envs/qgis310-deps-openssl/include
  LIBS += -L /opt/mc3/envs/qgis310-deps-openssl/lib -lcrypto -lssl
}

SOURCES += qsslkey-p11.cpp

DISTFILES += \
  CMakeLists.txt \
  openssl-test/test-client_conda-openssl.cnf \
  run.sh
