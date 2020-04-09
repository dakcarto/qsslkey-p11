#include <QtCore/QThread>
#include <QtCore/QFile>
#include <QtCore/QEventLoop>
#include <QtCore/QTimer>
#include <QtWidgets/QApplication>
#include <QtWidgets/QInputDialog>
#include <QtNetwork/QHostAddress>
#include <QtNetwork/QHostInfo>
#include <QtNetwork/QNetworkProxy>
#include <QtNetwork/QSslConfiguration>
#include <QtNetwork/QSslCipher>
#include <QtNetwork/QSslKey>
#include <QtNetwork/QSslSocket>
#include <QtNetwork/QTcpServer>

#include "qgspkcs11.h"


#define VERIFY(x)                                   \
    do {                                            \
        if (!(x)) {                                 \
            fprintf(stderr, "%s failed\n", #x);     \
            return 1;                                \
        }  else {                                   \
            fprintf(stderr, "%s passed\n", #x);     \
        }                                           \
    } while (0)


static QgsPKCS11 *mPKCS11 = Q_NULLPTR;
static EVP_PKEY *mEvpKey = Q_NULLPTR;

static bool pkcs11Init(const QString & pkcs11Module)
{

  mPKCS11 = new QgsPKCS11(nullptr, pkcs11Module);

  if (! mPKCS11->moduleLoaded()) {
    qWarning("QgsPKCS11 could not be initialized!");
    return false;
  }

  if (mPKCS11->slotCount() < 1) {
    qWarning("QgsPKCS11 could not locate any slots!");
    return false;
  }

  return true;
}


static bool pkcs11LoadBundle(const QString & certHash, QSslCertificate & cert, QSslKey & key) {

  QList<unsigned long> t_slots = mPKCS11->slotIdsWithToken();
  if (t_slots.length() < 1) {
    qWarning("QgsPKCS11 could not locate any slots with tokens!");
    return false;
  }

  QMap<unsigned long, QList<QSslCertificate> > sid_certs = mPKCS11->slotIdsWithCerts(false, certHash);
  if (t_slots.length() < 1) {
    qWarning("QgsPKCS11 could not locate any certs with SHA1 of: %s", qUtf8Printable(certHash));
    return false;
  }

  /* Load first matching certificate */
  QList<QSslCertificate> certs = sid_certs.first();
  if (certs.length() <= 0) {
    qWarning("QgsPKCS11 did not return any certs with SHA1 of: %s", qUtf8Printable(certHash));
    return false;
  }
  cert = certs.first();


//  { /* Load private key */
//      if (!mEvpKey) {
//          qWarning("Unable to load private key from HSM: %s",
//                   ERR_reason_error_string(ERR_get_error()));
//      }

//  //        qDebug() << EVP_PKEY_id(evp_pky);

//  //        if (!EVP_PKEY_set_type(evp_pky, 0)) {
//  //            qWarning("Unable to set type of private key");
//  //            goto error;
//  //        }

//  //        evp_pky_h = Qt::HANDLE(evp_pky);

//      key = QSslKey(Qt::HANDLE(mEvpKey), QSsl::PrivateKey);
//  }

  return true;

}


int test(const QString &pkcs11Module = QString(), const QString &certHash = QString(), const QString &pin = QString())
{
    QSslSocket socket;
    QSslKey key;
    QSslCertificate cert;

    if (! pkcs11Module.isEmpty()) {

      if (! pkcs11Init(pkcs11Module)) {
        qWarning("Unable initialize PKCS#11 module: %s", qUtf8Printable(pkcs11Module));
          return 1;
      } else {
        qDebug("PKCS#11 module initialized: %s", qUtf8Printable(pkcs11Module));
      }



      if (certHash.isEmpty()) {
        qDebug("No cert hash arg supplied, exiting");
        return 0;
      }

      if (! pkcs11LoadBundle(certHash, cert, key)) {
          qWarning("Unable load cert/key for SHA1: %s", qUtf8Printable(certHash));
          return 1;
      }

//        if (!key.isNull() && key.algorithm() != QSsl::Opaque) {
//            qCritical("QSslKey is not Opaque");
//            return 1;
//        }
    } else {
      qDebug("No PKCS#11 module defined; using default PEM cert/key...");
      QFile file(QLatin1String("certs/client-key.pem"));
      VERIFY(file.open(QIODevice::ReadOnly));
      key = QSslKey(file.readAll(), QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey, "");

      QList<QSslCertificate> localCert = QSslCertificate::fromPath(QLatin1String("certs/client-cert.pem"));
      VERIFY(!localCert.isEmpty());
      cert = localCert.first();
    }

    VERIFY(!key.isNull());
    qDebug() << key;
    // QSslKey(PrivateKey, Opaque, -1) or QSslKey(PrivateKey, RSA, 2048)

//    EVP_PKEY* evp_k = reinterpret_cast<EVP_PKEY *>(key.handle());

//    if (evp_k) {
//        qDebug() << EVP_PKEY_id(evp_k);
//    }

    socket.setPrivateKey(key);

    VERIFY(!cert.isNull());
    qDebug("Cert name: %s", cert.subjectInfo( QSslCertificate::CommonName ).value(0).toUtf8().constData());

    socket.setLocalCertificate(cert);

    socket.addCaCertificates("certs/ca-chains.pem");
    socket.setProtocol(QSsl::TlsV1_2);
    socket.setPeerVerifyMode(QSslSocket::VerifyPeer);

//    socket.connectToHostEncrypted("server.planet.local", 8443);
    socket.connectToHostEncrypted("openssl.planet.local", 4443);

//    socket.ignoreSslErrors();

    VERIFY(socket.waitForConnected(1000));

    VERIFY(socket.waitForEncrypted(10000));

    if (socket.isEncrypted()) {
      qDebug("Encrypted connection SUCCEEDED");
      socket.abort();
      return 0;
    }

    qWarning("Encrypted connection FAILED");
    socket.abort();
    return 1;
}

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QStringList args = app.arguments();

    if (args.size() == 4) {
      return test(args.at(1), args.at(2), args.at(3));
    } else if (args.size() == 3) {
      return test(args.at(1), args.at(2));
    } else if (args.size() == 2) {
      return test(args.at(1));
    } else if (args.size() == 1) {
      return test();
    } else {
      qCritical("qsslkey-p11 [pkcs11_module] [cert_sha1_hash] [Token PIN]");
      return 1;
    }

}

//#include "qsslkey-p11.moc"
