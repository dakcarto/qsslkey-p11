/***************************************************************************
    qgspkcs11.h
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

#ifndef QGSPKCS11_H
#define QGSPKCS11_H

#include <QObject>
#include <QSslCertificate>

#include <libp11.h>


class QgsPKCS11 : public QObject
{
  Q_OBJECT

  public:
    explicit QgsPKCS11(QObject *parent = nullptr, const QString &module = QString());

    ~QgsPKCS11() override;

    bool moduleLoaded() { return mModLoaded; }

    bool tokenLoggedInto(unsigned long slotId = 0);
    bool logIntoToken(unsigned long slotId = 0, const QString &pin = QString());

    unsigned int slotCount() { return mNSlots; }

    QList<unsigned long> slotIdsWithToken();

    QMap<unsigned long, QList<QSslCertificate> > slotIdsWithCerts(
        bool clientOnly = false, const QString &sha1Match = QString());

    QSslKey certificatePrivateKey(unsigned long slot = 0,
                                  bool clientOnly = false,
                                  const QString &sha1Match = QString());

  signals:


  private:
    void freeContext();
    void unloadContext();
    void freeSlots();

    bool loadSlots();
    PKCS11_SLOT *slotById(unsigned long slot = 0);
    QList<PKCS11_SLOT *> slotsWithToken(bool dumpInfo = false);
    QMap<PKCS11_SLOT *, QPair<PKCS11_CERT *, unsigned int> > slotsWithCerts(
        bool clientOnly = false, const QString &sha1Match = QString());
    QPair<PKCS11_CERT *, unsigned int> certsInToken(PKCS11_SLOT *slot);
    const QString dumpSlotInfo(PKCS11_SLOT *slot);
    void dumpSlots(PKCS11_SLOT *slots);

    QSslCertificate firstPkcs11QSslCertificate(PKCS11_CERT * pkcs11_cert);
    QList<QSslCertificate> pkcs11QSslCertificates(QPair<PKCS11_CERT *, unsigned int> pkcs11_certs);
    QPair<PKCS11_CERT *, unsigned int> filterPkcs11Certificates(QPair<PKCS11_CERT *, unsigned int> pkcs11_certs);

    static QByteArray QByteArray_from_X509(X509 *x509 = nullptr, QSsl::EncodingFormat format = QSsl::Pem);
    //! Gets string with colon delimiters every 2 characters
    static QString getColonDelimited( const QString &txt );
    static QString shaHexForCert( const QSslCertificate &cert,
                                  bool formatted = false );



    bool mModLoaded;
    QString mModule;
    PKCS11_CTX *mCtx;
    PKCS11_SLOT *mSlots;
    unsigned int mNSlots;
    PKCS11_CERT *mCerts;
};

#endif // QGSPKCS11_H