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

#include "qgspkcs11.h"

#include <libp11.h>
#include <QFileInfo>
#include <QSslCertificate>
#include <QSslKey>


QgsPKCS11::QgsPKCS11(QObject *parent, const QString &module)
  : QObject(parent),
    mModLoaded(false),
    mModule(module),
    mCtx(nullptr),
    mSlots(nullptr),
    mNSlots(0)
{
  // Check if module is available
  if ( mModule.isEmpty() || ! QFileInfo::exists( mModule ) ) {
    qDebug( "PKCS#11 module empty or not found: %s", qUtf8Printable( mModule ) );
  }

  OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
          | OPENSSL_INIT_ADD_ALL_DIGESTS \
          | OPENSSL_INIT_LOAD_CONFIG, Q_NULLPTR);

  // Set up PKCS context
  if ( ! mCtx ) {
    mCtx = PKCS11_CTX_new();
  }

  if ( ! mCtx ) {
    qWarning( "PKCS11_CTX could not be initialized" );
  } else {
    qWarning( "PKCS11_CTX initialized" );
    // Load the module
    qDebug( "Attempting to load PKCS#11 module: %s", qUtf8Printable( mModule ) );
    if (PKCS11_CTX_load(mCtx, qUtf8Printable(mModule)) == -1) {
      qWarning( "PKCS11_CTX could not be loaded: %s", ERR_reason_error_string(ERR_get_error()) );
    } else {
      qDebug( "PKCS#11 module loaded: %s", qUtf8Printable( mModule ) );
      mModLoaded = true;
      loadSlots();
    }

  }

}

QgsPKCS11::~QgsPKCS11()
{
  freeSlots();
  unloadContext();
  freeContext();
}

void QgsPKCS11::freeContext()
{
  if (mCtx) {
    PKCS11_CTX_free(mCtx);
  }
}

void QgsPKCS11::unloadContext()
{
  if (mCtx) {
    PKCS11_CTX_unload(mCtx);
  }
}

void QgsPKCS11::freeSlots()
{
  if (mNSlots > 0 && mSlots && mCtx) {
    PKCS11_release_all_slots(mCtx, mSlots, mNSlots);
  }
}

bool QgsPKCS11::loadSlots()
{
  if (! moduleLoaded()) {
    qWarning("No PKCS#11 module loaded to locate slots!");
    return false;
  }

  // Load slots
  if (PKCS11_enumerate_slots(mCtx, &mSlots, &mNSlots) == -1) {
    qWarning("Not slots available!");
  } else {
    qDebug("Slots enumerated");
  }
  return true;
}

PKCS11_SLOT *QgsPKCS11::slotById(unsigned long slot)
{
  if (! moduleLoaded()) {
    qWarning("No PKCS#11 module loaded to locate slots!");
    return nullptr;
  }

  if (! slot) {
    qWarning("No slot id defined!");
    return nullptr;
  }

  unsigned int m;
  for ( m = 0; m < mNSlots; m++ ) {
    PKCS11_SLOT *m_slot = mSlots + m;
    if (slot == PKCS11_get_slotid_from_slot(m_slot)) {
      return m_slot;
    }
  }

  return nullptr;
}

bool QgsPKCS11::tokenLoggedInto(unsigned long slotId)
{

}

bool QgsPKCS11::logIntoToken(unsigned long slotId, const QString &pin)
{

}

QList<PKCS11_SLOT *> QgsPKCS11::slotsWithToken(bool dumpInfo)
{
  QList<PKCS11_SLOT *> t_slots;

  if (! moduleLoaded()) {
    qWarning("No PKCS#11 module loaded to locate slots with tokens!");
    return t_slots;
  }

  if (mNSlots < 1) {
    return t_slots;
  }

  /* Get slots with a token */
  PKCS11_SLOT *slot;
  for (slot = PKCS11_find_token(mCtx, mSlots, mNSlots);
       slot != nullptr;
       slot = PKCS11_find_next_token(mCtx, mSlots, mNSlots, slot)) {
    t_slots.append(slot);
    if (dumpInfo) {
      qDebug("%s", qUtf8Printable(dumpSlotInfo(slot)));
    }
  }

  if (dumpInfo) {
    qDebug("Slots with tokens: %d", t_slots.count());
  }

  return t_slots;
}

QList<unsigned long> QgsPKCS11::slotIdsWithToken()
{
  QList<unsigned long> t_slots;

  for (PKCS11_SLOT * slot : slotsWithToken(true)) {
    t_slots.append(PKCS11_get_slotid_from_slot(slot));
  }

  return t_slots;
}

QMap<PKCS11_SLOT *, QPair<PKCS11_CERT *, unsigned int> > QgsPKCS11::slotsWithCerts(
    bool clientOnly, const QString &sha1Match)
{
  QMap<PKCS11_SLOT *, QPair<PKCS11_CERT *, unsigned int> > s_certs;
  QPair<PKCS11_CERT *, unsigned int> t_certs;

  for (PKCS11_SLOT * slot : slotsWithToken()) {
    t_certs = certsInToken(slot);
    if (t_certs.second > 0) {
      s_certs.insert(slot, t_certs);
    }
  }

  return s_certs;
}

QMap<unsigned long, QList<QSslCertificate> > QgsPKCS11::slotIdsWithCerts(
    bool clientOnly, const QString &sha1Match)
{
  QMap<unsigned long, QList<QSslCertificate> > sid_certs;
  QMap<PKCS11_SLOT *, QList<QSslCertificate> > s_certs = slotsWithCerts(clientOnly, sha1Match);

  for(auto slot : s_certs.keys()) {
    sid_certs.insert(PKCS11_get_slotid_from_slot(slot), s_certs.value(slot));
  }

  return sid_certs;
}

QPair<PKCS11_CERT *, unsigned int> QgsPKCS11::certsInToken(PKCS11_SLOT *slot)
{
  PKCS11_CERT *t_certs;
  unsigned int ncerts;

  if (! slot || slot->token == nullptr) {
    qWarning("No slot or token to parse certs from!");
    return QPair<PKCS11_CERT *, unsigned int>(t_certs, 0);
  }

  QString slot_dec(slot->description);

  if (PKCS11_enumerate_certs(slot->token, &t_certs, &ncerts) == -1) {
    qDebug("No enumerated certs found for token in slot: %s", qUtf8Printable(slot_dec));
    return QPair<PKCS11_CERT *, unsigned int>(t_certs, 0);
  }

  if (ncerts <= 0) {
    qDebug("No certs returned from token in slot: %s", qUtf8Printable(slot_dec));
    return QPair<PKCS11_CERT *, unsigned int>(t_certs, 0);
  }

  qDebug("%d cert(s) returned from token in slot: %s", ncerts, qUtf8Printable(slot_dec));

  return QPair<PKCS11_CERT *, unsigned int>(t_certs, ncerts);
}

QSslKey QgsPKCS11::certificatePrivateKey(
    unsigned long slot, bool clientOnly, const QString &sha1Match)
{

}
const QString QgsPKCS11::dumpSlotInfo(PKCS11_SLOT *slot)
{
  QString msg;
  msg += QString("Slot manufacturer......: %1\n").arg(slot->manufacturer);
  msg += QString("Slot description.......: %1\n").arg(slot->description);
  msg += QString("Slot token label.......: %1\n").arg(slot->token->label);
  msg += QString("Slot token manufacturer: %1\n").arg(slot->token->manufacturer);
  msg += QString("Slot token model.......: %1\n").arg(slot->token->model);
  msg += QString("Slot token serialnr....: %1\n").arg(slot->token->serialnr);

  return msg;
}

QSslCertificate QgsPKCS11::firstPkcs11QSslCertificate(PKCS11_CERT *pkcs11_cert)
{
  PKCS11_CERT * fist_cert = &pkcs11_cert[0];
  return QSslCertificate(QByteArray_from_X509(fist_cert->x509));
}

QList<QSslCertificate> QgsPKCS11::pkcs11QSslCertificates(QPair<PKCS11_CERT *, unsigned int> pkcs11_certs)
{
  unsigned int m;
  QSslCertificate cert;
  QList<QSslCertificate> certs;
  PKCS11_CERT * t_certs = pkcs11_certs.first;
  unsigned int ncerts = pkcs11_certs.second;

  for ( m = 0; m < ncerts; m++ ) {
    PKCS11_CERT *t_cert = t_certs + m;
    cert = QSslCertificate(QByteArray_from_X509(t_cert->x509));
//    X509_free(t_cert->x509);

    // TODO: filter by clientOnly

    if (! sha1Match.isEmpty()) {
      qDebug("SHA1 cert-matching for token in slot: %s", qUtf8Printable(slot_dec));
      if (shaHexForCert(cert) != sha1Match) {
        continue;
      }
      qDebug("Found SHA1 match!");
    }
    certs.append(cert);
  }

  return certs;
}

QPair<PKCS11_CERT *, unsigned int> QgsPKCS11::filterPkcs11Certificates(
    QPair<PKCS11_CERT *, unsigned int> pkcs11_certs,
    bool clientOnly, const QString &sha1Match)
{


  // Calculate SHA1 fingerprint
  int pos;
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int dn;
  // digest = EVP_get_digestbyname("sha1");
  X509_digest(authcert->x509, EVP_sha1(), md, &dn);
  printf("\nSHA-1 Fingerprint: ");
  for(pos = 0; pos < 19; pos++)
    printf("%02x:", md[pos]);
  printf("%02x\n", md[19]);

}

void dumpSlots(PKCS11_SLOT *slots) {

}

QByteArray QgsPKCS11::QByteArray_from_X509(X509 *x509, QSsl::EncodingFormat format) {
    if (!x509) {
        qWarning("X509_to_QByteArray: null X509 passed");
        return QByteArray();
    }

    // Use i2d_X509 to convert the X509 to an array.
    int length = i2d_X509(x509, nullptr);
    QByteArray array;
    array.resize(length);
    char *data = array.data();
    char **dataP = &data;
    unsigned char **dataPu = (unsigned char **)dataP;
    if (i2d_X509(x509, dataPu) < 0)
        return QByteArray();

    if (format == QSsl::Der)
        return array;

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

QString QgsPKCS11::getColonDelimited(const QString &txt)
{
  // 64321c05b0ebab8e2b67ec0d7d9e2b6d4bc3c303
  // -> 64:32:1c:05:b0:eb:ab:8e:2b:67:ec:0d:7d:9e:2b:6d:4b:c3:c3:03
  QStringList sl;
  sl.reserve( txt.size() );
  for ( int i = 0; i < txt.size(); i += 2 )
  {
    sl << txt.mid( i, ( i + 2 > txt.size() ) ? -1 : 2 );
  }
  return sl.join( QStringLiteral( ":" ) );
}

QString QgsPKCS11::shaHexForCert(const QSslCertificate &cert, bool formatted)
{
  QString sha( cert.digest( QCryptographicHash::Sha1 ).toHex() );
  if ( formatted )
  {
    return getColonDelimited( sha );
  }
  return sha;
}
