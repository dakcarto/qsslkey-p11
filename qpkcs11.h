/***************************************************************************
    qpkcs11.h
    ---------------------
    begin                : January, 2020
    copyright            : (C) 2020 Planet Labs Inc, https://planet.com
    author               : Larry Shaffer, Planet Federal
 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#ifndef QPKCS11_H
#define QPKCS11_H

#include <QObject>
#include <QSslCertificate>

#include <libp11.h>


class QPkcs11 : public QObject
{
  Q_OBJECT

  public:

    explicit QPkcs11(QObject *parent = nullptr, const QString &module = QString());

    ~QPkcs11() override;

    bool moduleLoaded();


    bool tokenLoggedIn(const QString &slotId = QString());

    bool logIntoToken(const QString &slotId = QString(), const QString &pin = QString());


    QStringList slotIdsAvailable() { return mSlotsAvailable.keys(); }

    QStringList slotIdsWithToken();

    QMap<QString, QList<QSslCertificate> > slotIdsWithCerts(
        const QString &sha1Match = QString(), bool clientOnly = true);


    QPair<QString, QSslCertificate> firstMatchingCertificate(
        const QString &sha1Match, bool clientOnly = true);

    QSslKey certificatePrivateKey(const QString &sha1Match = QString(),
                                  bool clientOnly = true);


  signals:

    void moduleLoadedChanged(bool moduleLoaded);

    void tokenRemovedFromSlot(const QString &slotId);

    void tokenInsertedInSlot(const QString &slotId);

    void messageLogged(const QString &msg, QtMsgType type);


  public slots:

    void loadSlots();

    void parseSlotsForToken(bool dumpInfo = false);


  private:

    void logMsg(const QString &msgTxt = QString(), QtMsgType msgType = QtDebugMsg);

    void freeContext();

    void unloadContext();

    void unloadModule();

    void releaseSlots();


    bool loadContext();

    bool loadModule();

    bool reloadContextAndSlots();


    PKCS11_SLOT *slotById(const QString &slotId = QString());

    QString idForSlot(PKCS11_SLOT *slot);

    QString uniqueSlotId();

    QList<PKCS11_SLOT *> slotsWithToken() { return mSlotsWithToken; }

    QMap<PKCS11_SLOT *, QList<PKCS11_CERT *> > slotsWithTokenCerts(
        const QString &sha1Match = QString(), bool clientOnly = true );

    QList<PKCS11_CERT *> tokenCertsInSlot(PKCS11_SLOT *slot);

    const QString dumpSlotInfo(PKCS11_SLOT *slot);
    void dumpSlots(QList<PKCS11_SLOT *> t_slots);


    QPair<PKCS11_SLOT *, PKCS11_CERT *> firstMatchingPkcs11Certificate(
        const QString &sha1Match = QString(), bool clientOnly = true);

    QSslCertificate firstPkcs11QSslCertificate(PKCS11_CERT * pkcs11_cert);

    QList<QSslCertificate> pkcs11QSslCertificates(QList<PKCS11_CERT *> pkcs11_certs);

    QList<PKCS11_CERT *> filterPkcs11Certificates(QList<PKCS11_CERT *> pkcs11_certs,
        const QString &sha1Match = QString(), bool clientOnly = true);


    static QByteArray QByteArray_from_X509(X509 *x509 = nullptr, QSsl::EncodingFormat format = QSsl::Pem);

    //! Gets string with colon delimiters every 2 characters
    static QString getColonDelimited( const QString &txt );

    static QString shaHexForCert( const QSslCertificate &cert,
                                  bool formatted = false );

    static QString shaHexForOpenSslCert( X509 *x509 = nullptr,
                                         bool formatted = false );


    bool mLogEnabled;
    bool mModLoaded;
    QString mModule;
    PKCS11_CTX *mCtx;
    PKCS11_SLOT *mSlots;
    unsigned int mNSlots;
    QHash<QString, PKCS11_SLOT *> mSlotsAvailable;
    QList<PKCS11_SLOT *> mSlotsWithToken;
};

#endif // QPKCS11_H
