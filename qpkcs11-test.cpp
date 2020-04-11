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

#include "qpkcs11.h"


#define VERIFY(x)                                   \
    do {                                            \
        if (!(x)) {                                 \
            fprintf(stderr, "%s failed\n", #x);     \
            return 1;                                \
        }  else {                                   \
            fprintf(stderr, "%s passed\n", #x);     \
        }                                           \
    } while (0)


static QPkcs11 *mPKCS11 = Q_NULLPTR;
//static EVP_PKEY *mEvpKey = Q_NULLPTR;

static bool pkcs11Init(const QString & pkcs11Module)
{

  mPKCS11 = new QPkcs11(nullptr, pkcs11Module);

  if (! mPKCS11->moduleLoaded()) {
    qWarning("QPkcs11 could not be initialized!");
    return false;
  }

  if (mPKCS11->slotIdsAvailable().length() < 1) {
    qWarning("QPkcs11 could not locate any slots!");
    return false;
  }

  return true;
}


static bool pkcs11LoadBundle(const QString & certHash, QSslCertificate & cert, QSslKey & key, const QString &pin = QString()) {

  QStringList t_slots = mPKCS11->slotIdsAvailable();
  if (t_slots.length() < 1) {
    qWarning("QPkcs11 could not locate any slots with tokens!");
    return false;
  }

  QPair<QString, QSslCertificate> sid_cert = mPKCS11->firstMatchingCertificate(certHash, true);

  QSslCertificate s_cert = sid_cert.second;
  if (s_cert.isNull()) {
    qWarning("QPkcs11 did not return a valid cert that matched SHA1: %s", qUtf8Printable(certHash));
    return false;
  }
  //qDebug("QPkcs11 returned a valid cert that matched SHA1: %s", qUtf8Printable(certHash));
  cert = s_cert;

  QString token_slot = sid_cert.first;
  //qDebug("QPkcs11 returned a cert that matched SHA1 for slot ID: %s", qUtf8Printable(token_slot));

  // Log into slot's token
  if (! mPKCS11->logIntoToken(token_slot, pin)) {
    qWarning("QPkcs11 could not log into token with cert that matched SHA1: %s", qUtf8Printable(certHash));
    return false;
  }

  // Load private key, via OpenSSL handle
  key = mPKCS11->certificatePrivateKey(certHash, true);
  if (key.isNull()) {
    qWarning("QPkcs11 did not return a valid cert private key that matched SHA1: %s", qUtf8Printable(certHash));
    return false;
  }

  return true;
}

static int secureConnection(QSslSocket &socket, const QString &url, quint16 port)
{
      socket.connectToHostEncrypted(url, port);

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


int test(const QString &pkcs11Module = QString(), const QString &certHash = QString(), const QString &pin = QString())
{
    QSslSocket socket;
    QSslKey key;
    QSslCertificate cert;

    if (! pkcs11Module.isEmpty()) {

      if (! pkcs11Init(pkcs11Module)) {
        qWarning("Unable initialize PKCS#11 module: %s", qUtf8Printable(pkcs11Module));
          return 1;
      }

      if (certHash.isEmpty()) {
        qDebug("No cert hash arg supplied, exiting");
        return 0;
      }

      if (! pkcs11LoadBundle(certHash, cert, key, pin)) {
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

    qDebug("\nSetting up QSslSocket...");

    //VERIFY(!cert.isNull());
    qDebug("  cert name: %s", cert.subjectInfo( QSslCertificate::CommonName ).value(0).toUtf8().constData());

    socket.setLocalCertificate(cert);


    //VERIFY(!key.isNull());
    qDebug() << "  key type:" << key;
    // QSslKey(PrivateKey, Opaque, -1) or QSslKey(PrivateKey, RSA, 2048)

//    EVP_PKEY* evp_k = reinterpret_cast<EVP_PKEY *>(key.handle());

//    if (evp_k) {
//        qDebug() << EVP_PKEY_id(evp_k);
//    }

    socket.setPrivateKey(key);

    socket.addCaCertificates("certs/ca-chains.pem");
    socket.setProtocol(QSsl::TlsV1_2);
    socket.setPeerVerifyMode(QSslSocket::VerifyPeer);

//    QString url("server.planet.test");
//    quint16 port(8443);
    QString url("openssl.planet.local");
    quint16 port(4443);
    int res;

    qDebug("\nStarting secure connection...");
    res = secureConnection(socket, url, port);

//    unsigned long sleep_secs = 5;

//    qDebug("Sleep for %ld seconds...", sleep_secs);
//    QThread::sleep(sleep_secs);

//    qDebug("\nStarting second secure connection...");
//    res = secureConnection(socket, url, port);

//    qDebug("Sleep for %ld seconds...", sleep_secs);
//    QThread::sleep(sleep_secs);

//    qDebug("\nStarting third secure connection...");
//    res = secureConnection(socket, url, port);

    return res;
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
