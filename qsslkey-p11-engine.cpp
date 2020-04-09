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
#include <QtNetwork/QSslKey>
#include <QtNetwork/QSslSocket>
#include <QtNetwork/QTcpServer>

#define USE_PKCS11

#ifdef USE_PKCS11
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#define HEADER_STORE_H  /* avoid openssl/store.h inclusion, break compil */
#include <openssl/engine.h>
#endif

class AuthServer : public QTcpServer
{
    Q_OBJECT
public:
    AuthServer() : socket(Q_NULLPTR) {
//        connect(this, &QTcpServer::newConnection, this, &AuthServer::sendResponse);
    }
    QSslSocket *socket;

protected:
    void incomingConnection(qintptr socketDescriptor)
    {
        socket = new QSslSocket(this);
        socket->setSocketDescriptor(socketDescriptor);

        socket->setPrivateKey("certs/server-key.pem",  QSsl::Rsa, QSsl::Pem);
        socket->setLocalCertificate("certs/server-cert.pem");
        socket->addCaCertificates("certs/client-ca.pem");
        socket->setProtocol(QSsl::TlsV1_2);
        socket->setPeerVerifyMode(QSslSocket::VerifyPeer);
        socket->startServerEncryption();

        connect(socket, &QSslSocket::encrypted, this, &AuthServer::socketEncrypted);
        connect(socket, static_cast<void(QSslSocket::*)(const QList<QSslError> &)>(&QSslSocket::sslErrors),
                this, &AuthServer::onSslErrors);

        this->addPendingConnection(socket);
    }

signals:
    void authenticated();


public slots:
    void onSslErrors( const QList<QSslError> &errors )
    {
        qDebug( "SSL Errors: " );
        for ( auto end = errors.size(), i = 0; i != end; ++i )
        {
          qDebug() << errors[i].errorString();
        }
    }

private slots:
    void socketEncrypted()
    {
        qDebug() << socket->peerCertificate();
        // Very basic authentication, check that the client is using the same certificate
//        if (socket->peerCertificate() != socket->localCertificate()) {
//            qDebug() << socket->peerCertificate();
//            qDebug() << socket->localCertificate();
//            socket->abort();
//        } else
//            emit authenticated();
        this->sendResponse();
    }

    void sendResponse()
    {
        qDebug("Sending response");

        QTcpSocket *clientConnection = nextPendingConnection();

        if (!clientConnection) {
            qDebug("No pending connection socket");
            return;
        }

        connect(clientConnection, &QAbstractSocket::disconnected,
                clientConnection, &QObject::deleteLater);
        clientConnection->write("HTTP/1.1 200 OK\r\n"
                                "Content-type: text/plain\r\n"
                                "Content-length: 17\r\n"
                                "\r\n"
                                "Connected via PKI");
        clientConnection->disconnectFromHost();
    }

};

#define VERIFY(x)                                   \
    do {                                            \
        if (!(x)) {                                 \
            fprintf(stderr, "%s failed\n", #x);     \
            return ;                                \
        }  else {                                   \
            fprintf(stderr, "%s passed\n", #x);     \
        }                                           \
    } while (0)

#ifdef USE_PKCS11
static QByteArray QByteArray_from_X509(X509 *x509)
{
    if (!x509) {
        qWarning("QSslSocketBackendPrivate::X509_to_QByteArray: null X509");
        return QByteArray();
    }

    // Use i2d_X509 to convert the X509 to an array.
    int length = i2d_X509(x509, Q_NULLPTR);
    QByteArray array;
    array.resize(length);
    char *data = array.data();
    char **dataP = &data;
    unsigned char **dataPu = (unsigned char **)(dataP);
    if (i2d_X509(x509, dataPu) < 0)
        return QByteArray();

    // Convert to Base64 - wrap at 64 characters.
    array = array.toBase64();
    QByteArray tmp;
    for (int i = 0; i <= array.size() - 64; i += 64) {
        tmp += QByteArray::fromRawData(array.data() + i, 64);
        tmp += '\n';
    }
    if (int remainder = array.size() % 64) {
        tmp += QByteArray::fromRawData(array.data() + array.size() - remainder, remainder);
        tmp += '\n';
    }

    return "-----BEGIN CERTIFICATE-----\n" + tmp + "-----END CERTIFICATE-----\n";
}

static int ui_read(UI *ui, UI_STRING *uis)
{
    if (UI_get_string_type(uis) != UIT_PROMPT) {
        qWarning("unsupported UI string type (%u)\n", UI_get_string_type(uis));
        return 0;
    }

    QString value = QInputDialog::getText(Q_NULLPTR, "Enter PIN code",
                                          QString(UI_get0_output_string(uis)),
                                          QLineEdit::Password);

    UI_set_result(ui, uis, value.toLatin1().data());

    return 1;
}

static ENGINE *ssl_engine = Q_NULLPTR;
static EVP_PKEY *evp_pky = Q_NULLPTR;
static Qt::HANDLE evp_pky_h = Q_NULLPTR;

static void pkcs11_init(const QString & pkcs11_engine,
                        const QString & pkcs11_module, const QString & keyid,
                        QSslCertificate & certificate, QSslKey & key)
{
    ENGINE *e;

//#if OPENSSL_VERSION_NUMBER>=0x10100000
//    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
//            | OPENSSL_INIT_ADD_ALL_DIGESTS \
//            | OPENSSL_INIT_LOAD_CONFIG, Q_NULLPTR);
//#else
//    OpenSSL_add_all_algorithms();
//    OpenSSL_add_all_digests();
//    ERR_load_crypto_strings();
//#endif
    ERR_clear_error();

    /* Probably already done by Qt */
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();

//    ENGINE_load_builtin_engines();

//    e = ENGINE_by_id("pkcs11");
//    if (!e) {
//        qWarning("Unable to load pkcs11 engine: %s",
//                 ERR_reason_error_string(ERR_get_error()));
//        goto error;
//    }


    ENGINE_load_dynamic();
    ERR_clear_error();

    e = ENGINE_by_id("dynamic");
    if (!e) {
        qWarning("Unable to load dynamic engine: %s",
                 ERR_reason_error_string(ERR_get_error()));
        goto error;
    }

    if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", pkcs11_engine.toLocal8Bit().data(), 0) ||
        !ENGINE_ctrl_cmd_string(e, "ID", "pkcs11", 0) ||
        !ENGINE_ctrl_cmd_string(e, "LIST_ADD", "1", 0) ||
        !ENGINE_ctrl_cmd_string(e, "LOAD", Q_NULLPTR, 0) ||
        !ENGINE_ctrl_cmd_string(e, "MODULE_PATH", pkcs11_module.toLocal8Bit().data(), 0) ||
        !ENGINE_ctrl_cmd_string(e, "VERBOSE", Q_NULLPTR, 0) ||
        !ENGINE_ctrl_cmd_string(e, "FORCE_LOGIN", Q_NULLPTR, 0) ||
        !ENGINE_ctrl_cmd_string(e, "PIN", "9900", 0) ||
        !ENGINE_init(e)
        /*!ENGINE_set_default(e, ENGINE_METHOD_ALL)*/) {
        qWarning("Unable to initialize PKCS#11 library: %s",
                 ERR_reason_error_string(ERR_get_error()));
        goto error;
    }
    //  ENGINE_init() returned a functional reference, so free the structural
    //  reference from ENGINE_by_id().
//    ENGINE_free(e);

    ENGINE_set_default(e, ENGINE_METHOD_ALL);

    { /* Load private key */
//        EVP_PKEY *k;
        UI_METHOD *ui_meth = UI_create_method("PIN prompt");

        UI_method_set_reader(ui_meth, ui_read);
        evp_pky = ENGINE_load_private_key(e, keyid.toLocal8Bit().data(), ui_meth, Q_NULLPTR);

        if (!evp_pky) {
            qWarning("Unable to load private key from HSM: %s",
                     ERR_reason_error_string(ERR_get_error()));
            goto error;
        }

//        qDebug() << EVP_PKEY_id(evp_pky);

//        if (!EVP_PKEY_set_type(evp_pky, 0)) {
//            qWarning("Unable to set type of private key");
//            goto error;
//        }

//        evp_pky_h = Qt::HANDLE(evp_pky);

        key = QSslKey(Qt::HANDLE(evp_pky), QSsl::PrivateKey);
    }

    { /* Load certificate */
        struct {
            const char *cert_id;
            X509 *cert;
        } params = { Q_NULLPTR, Q_NULLPTR };

        if (!ENGINE_ctrl_cmd(e, "LOAD_CERT_CTRL", 0, &params, Q_NULLPTR, 0))
            params.cert = Q_NULLPTR;

        if (!params.cert) {
            qWarning("Unable to load certificate from HSM");
            goto error;
        }

        certificate = QSslCertificate(QByteArray_from_X509(params.cert));
        X509_free(params.cert);

//        QList<QSslCertificate> localCert = QSslCertificate::fromPath(QLatin1String("certs/cert.pem"));
//        VERIFY(!localCert.isEmpty());
//        certificate = localCert.first();
    }

    ssl_engine = e;
    return;

error:
    if (evp_pky) {
        EVP_PKEY_free(evp_pky);
    }
    if (e) {
        ENGINE_free(e);
    }
    if (evp_pky_h) {
      evp_pky_h = Q_NULLPTR;
    }
}

static void pkcs11_clear()
{
    if (evp_pky) {
        EVP_PKEY_free(evp_pky);
    }
    if (ssl_engine) {
        ENGINE_finish(ssl_engine);
        ENGINE_free(ssl_engine);
    }
}
#endif
#include <QtNetwork/QSslCipher>
void test(const QString & pkcs11_engine, const QString & pkcs11_module = QString(), const QString & keyid = QString())
{
//    AuthServer server;
//    VERIFY(server.listen(QHostAddress::LocalHost, 9393));

//    server.waitForNewConnection(-1);
//    QEventLoop loop;
//    QTimer::singleShot(1000000, &loop, &QEventLoop::quit);
//    loop.exec();
//    return;

    QSslSocket socket;
    QSslKey key;
    QSslCertificate cert;

    if (!pkcs11_module.isEmpty()) {
        pkcs11_init(pkcs11_engine, pkcs11_module, keyid, cert, key);
//        if (!key.isNull() && key.algorithm() != QSsl::Opaque) {
//            qCritical("QSslKey is not Opaque");
//            return;
//        }
    } else {
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

//    QObject::connect(&socket, static_cast<void(QSslSocket::*)(const QList<QSslError> &)>(&QSslSocket::sslErrors),
//            &server, &AuthServer::onSslErrors);

//    socket.connectToHostEncrypted("local.planet.local", server.serverPort());
//    socket.connectToHostEncrypted("server.planet.local", 8443);
    socket.connectToHostEncrypted("openssl.planet.local", 4443);

    socket.ignoreSslErrors();

    VERIFY(socket.waitForConnected(10000));
//    VERIFY(server.waitForNewConnection(0));

//    if (socket.waitForEncrypted(5000)) {
//        qDebug("Connected to encrypted server");
//        VERIFY(server.socket->localCertificate() == socket.localCertificate());
//    } else {
//        qWarning("Connection to encrypted server timed out");
//    }

    QEventLoop loop;
    QTimer::singleShot(10000, &loop, &QEventLoop::quit);
    QObject::connect(&socket, &QSslSocket::encrypted, &loop, &QEventLoop::quit);
    QObject::connect(&socket, &QSslSocket::disconnected, &loop, &QEventLoop::quit);
    loop.exec();

    if (!socket.isEncrypted()) {
        qWarning("Encrypted connection FAILED");
    } else {
        qDebug("Encrypted connection SUCCEEDED");
    }

    socket.abort();

    pkcs11_clear();
}

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QStringList args = app.arguments();

    if (args.size() == 4) {
        test(args.at(1), args.at(2), args.at(3));
    } else if (args.size() == 3) {
        test(args.at(1), args.at(2));
    } else if (args.size() == 2) {
        test(args.at(1));
    } else {
        qCritical("qsslkey-p11-engine pkcs11_engine [pkcs11_module] [key_id]");
        return 1;
    }

    return 0;
}

#include "qsslkey-p11-engine.moc"
