/***************************************************************************
    qpkcs11.cpp
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

#include "qpkcs11.h"

#include <libp11.h>

#include <QEventLoop>
#include <QFileInfo>
#include <QSslCertificate>
#include <QSslKey>
#include <QTimer>


QPkcs11::QPkcs11(QObject *parent, const QString &module)
  : QObject(parent),
    mModLoaded(false),
    mModule(module),
    mCtx(nullptr),
    mSlots(nullptr),
    mNSlots(0)
{
  // Check if module is available
  if ( mModule.isEmpty() || ! QFileInfo::exists( mModule ) ) {
    logMsg(QStringLiteral( "PKCS#11 module empty or not found: %1").arg( mModule ), QtWarningMsg);
  } else {

  //  OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
  //          | OPENSSL_INIT_ADD_ALL_DIGESTS \
  //          | OPENSSL_INIT_LOAD_CONFIG, Q_NULLPTR);

    // Set up PKCS context
    if (loadContext()){
      if (loadModule()) {
        loadSlots();
      }
    }

  }

}

QPkcs11::~QPkcs11()
{
  releaseSlots();
  unloadContext();
  freeContext();
}


void QPkcs11::logMsg(const QString &msgTxt, QtMsgType msgType)
{
  switch ( msgType )
  {
    case QtDebugMsg:
      qDebug("%s", qUtf8Printable(msgTxt));
      break;
    case QtWarningMsg:
      qWarning("%s", qUtf8Printable(msgTxt));
      break;
    case QtCriticalMsg:
      qCritical("%s", qUtf8Printable(msgTxt));
      break;
    case QtFatalMsg:
      qFatal("%s", qUtf8Printable(msgTxt));
      //break;
    case QtInfoMsg:
      qInfo("%s", qUtf8Printable(msgTxt));
  }

  emit messageLogged(msgTxt, msgType);
}

void QPkcs11::freeContext()
{
  if (mCtx) {
    PKCS11_CTX_free(mCtx);
  }
}

void QPkcs11::unloadContext()
{
  if (mCtx) {
    PKCS11_CTX_unload(mCtx);
  }
}

void QPkcs11::unloadModule()
{
  if (! mModLoaded) {
    logMsg("No module loaded to unload", QtDebugMsg);
  }

  if ( ! mCtx ) {
    logMsg(QStringLiteral("PKCS11_CTX not be initialized, can not unload module"));
  }
  PKCS11_CTX_unload(mCtx);

  mModLoaded = false;
}

void QPkcs11::releaseSlots()
{
  if (mNSlots > 0 && mSlots && mCtx) {
    PKCS11_release_all_slots(mCtx, mSlots, mNSlots);
  }
}

bool QPkcs11::loadContext()
{
  if ( ! mCtx ) {
    mCtx = PKCS11_CTX_new();
  } else {
    logMsg(QStringLiteral("PKCS11 context already initialized"), QtDebugMsg);
    return true;
  }

  if ( ! mCtx ) {
    logMsg(QStringLiteral("PKCS11 context not be initialized"));
    return false;
  } else {
    logMsg(QStringLiteral("PKCS11 context initialized"), QtDebugMsg);
  }
  return true;
}

bool QPkcs11::moduleLoaded() // public
{
  if (! mModLoaded) {
    logMsg(QStringLiteral("No PKCS#11 module loaded!"));
    return false;
  }
  return true;
}

bool QPkcs11::loadModule()
{
  if (mModLoaded) {
    return true;
  }

  if ( ! mCtx ) {
    logMsg(QStringLiteral("PKCS11 context not initialized"));
    return false;
  } else {
    // Load the module
    logMsg(QStringLiteral("Loading PKCS#11 module: %1").arg(mModule), QtDebugMsg);
    if (PKCS11_CTX_load(mCtx, qUtf8Printable(mModule)) == -1) {
      logMsg(QStringLiteral( "  module could not be loaded: %1").arg(
               ERR_reason_error_string(ERR_get_error())), QtWarningMsg );
      mModLoaded = false;
    } else {
      logMsg("  module loaded", QtDebugMsg);
      mModLoaded = true;
    }
  }

  return mModLoaded;
}

void QPkcs11::loadSlots() // public slot
{
  if (! moduleLoaded()) {
    return;
  }

  // Load slots
  mSlotsAvailable.clear();
  mSlotsWithToken.clear();
  if (PKCS11_enumerate_slots(mCtx, &mSlots, &mNSlots) == -1) {
    logMsg(QStringLiteral("Not slots available!"), QtWarningMsg);
  } else {
    logMsg("Enumerating slots...", QtDebugMsg);
    logMsg(QStringLiteral("Slots found: %1").arg(mNSlots), QtDebugMsg);
    unsigned int m;
    for ( m = 0; m < mNSlots; m++ ) {
      PKCS11_SLOT *m_slot = mSlots + m;
      QString u_id = uniqueSlotId();
      mSlotsAvailable.insert(u_id, m_slot);
      logMsg(QStringLiteral("  id %1: %2").arg(u_id, m_slot->description), QtDebugMsg);
    }

    parseSlotsForToken();
  }
}

bool QPkcs11::reloadContextAndSlots()
{
  releaseSlots();
  unloadModule();
  unloadContext();

  if (!loadContext()) {
    return false;
  }
  if (!loadModule()) {
    return false;
  }
  loadSlots();

  return true;
}

PKCS11_SLOT *QPkcs11::slotById(const QString &slotId)
{
  if (! moduleLoaded()) {
    return nullptr;
  }

  if (slotId.isNull()) {
    logMsg(QStringLiteral("No slot id defined!"), QtWarningMsg);
    return nullptr;
  }

  if (mSlotsAvailable.contains(slotId)) {
    return mSlotsAvailable.value(slotId);
  }

  return nullptr;
}

QString QPkcs11::idForSlot(PKCS11_SLOT *slot)
{
  QString slotId;
  if (slot) {
    return mSlotsAvailable.key(slot, QString());
  }
  return slotId;
}

QString QPkcs11::uniqueSlotId()
{
  QString id;
  int len = 7;
  // sleep just a bit to make sure the current time has changed
  QEventLoop loop;
  QTimer::singleShot( 3, &loop, &QEventLoop::quit );
  loop.exec();

  uint seed = static_cast< uint >( QTime::currentTime().msec() );
  qsrand( seed );

  while ( true )
  {
    id.clear();
    for ( int i = 0; i < len; i++ )
    {
      switch ( qrand() % 2 )
      {
        case 0:
          id += ( '0' + qrand() % 10 );
          break;
        case 1:
          id += ( 'a' + qrand() % 26 );
          break;
      }
    }
    if ( !mSlotsAvailable.contains( id ) )
    {
      break;
    }
  }
  //logMsg(QStringLiteral("Generated unique slot ID: %1").arg(id), QtDebugMsg);
  return id;
}

bool QPkcs11::tokenLoggedIn(const QString &slotId) // public
{
  if (! moduleLoaded()) {
    return false;
  }

  if (slotId.isNull()) {
    logMsg(QStringLiteral("No slot id defined!"), QtWarningMsg);
    return false;
  }

  PKCS11_SLOT *slot = slotById(slotId);
  const char *slot_dec(slot->description);

//  if (slot->token->loginRequired) {
//    return false;
//  }

  int logged_in;
  if (PKCS11_is_logged_in(slot, 0, &logged_in) != 0) {
    logMsg(QStringLiteral("PKCS11_is_logged_in FAILED for slot: %1").arg(slot_dec), QtDebugMsg);
    return false;
  }

  if (! logged_in) {
    logMsg(QStringLiteral("User NOT LOGGED IN for slot: %1").arg(slot_dec), QtDebugMsg);
    return false;
  }

  logMsg(QStringLiteral("User LOGGED IN for slot: %1").arg(slot_dec), QtDebugMsg);
  return true;
}

bool QPkcs11::logIntoToken(const QString &slotId, const QString &pin) // public
{
  if (! moduleLoaded()) {
    return false;
  }

  if (tokenLoggedIn(slotId)) {
    return true;
  }

  PKCS11_SLOT *slot = slotById(slotId);
  const char *slot_dec(slot->description);

  logMsg(QStringLiteral("Trying to log into slot: %1").arg(slot_dec), QtDebugMsg);
  int res = PKCS11_login(slot, 0, pin.toUtf8().constData());

  // Clear the password in memory

  // (this is used in libp11 code)
  //   memset(pin, 0, strlen(pin));

  // From https://stackoverflow.com/a/44920544
  QString str2 = pin;
  QChar* chars = const_cast<QChar*>(pin.constData());
  for (int i = 0; i < pin.length(); ++i)
      chars[i] = '0';
  // pin and str2 are now both zeroed

  if ( res != 0 ) {
    logMsg(QStringLiteral("PKCS11_login FAILED!"));
    return false;
  }

  // Double check that login actual worked
  return tokenLoggedIn(slotId);
}

QStringList QPkcs11::slotIdsWithToken() // public
{
  QStringList t_slots;

  for (auto slot : mSlotsWithToken) {
      t_slots.append(idForSlot(slot));
  }

  return t_slots;
}


void QPkcs11::parseSlotsForToken(bool dumpInfo) // public slot
{
  mSlotsWithToken.clear();

  if (! moduleLoaded()) {
    return;
  }

  if (mNSlots < 1) {
    logMsg(QStringLiteral("No slots available for token parsing!"));
    return;
  }

  logMsg(QStringLiteral("Parsing slots for tokens..."));

  /* Get slots with a token */
  PKCS11_SLOT *slot;
  for (slot = PKCS11_find_token(mCtx, mSlots, mNSlots);
       slot != nullptr;
       slot = PKCS11_find_next_token(mCtx, mSlots, mNSlots, slot)) {
    mSlotsWithToken.append(slot);
  }

  logMsg(QStringLiteral("Slots found with tokens:  %1").arg(mSlotsWithToken.length()), QtDebugMsg);

  for (auto t_slot : mSlotsWithToken) {
    logMsg(QStringLiteral("  token label: %1").arg(t_slot->token->label), QtDebugMsg);
    if (dumpInfo) {
      logMsg(dumpSlotInfo(t_slot), QtDebugMsg);
    }
  }

}

QMap<PKCS11_SLOT *, QList<PKCS11_CERT *> > QPkcs11::slotsWithTokenCerts(
    const QString &sha1Match, bool clientOnly)
{
  QMap<PKCS11_SLOT *, QList<PKCS11_CERT *> > s_certs;

  if (! moduleLoaded()) {
    return s_certs;
  }

  QList<PKCS11_CERT *> t_certs;

  for (auto slot : slotsWithToken()) {
    t_certs = filterPkcs11Certificates(tokenCertsInSlot(slot), sha1Match, clientOnly);
    if (t_certs.length() > 0) {
      s_certs.insert(slot, t_certs);
    }
  }

  return s_certs;
}

QMap<QString, QList<QSslCertificate> > QPkcs11::slotIdsWithCerts(
    const QString &sha1Match, bool clientOnly) // public
{
  QMap<QString, QList<QSslCertificate> > sid_certs;

  if (! moduleLoaded()) {
    return sid_certs;
  }

  QMap<PKCS11_SLOT *, QList<PKCS11_CERT *> > s_certs = slotsWithTokenCerts(sha1Match, clientOnly);

  for(auto slot : s_certs.keys()) {
    sid_certs.insert(idForSlot(slot),
                     pkcs11QSslCertificates(s_certs.value(slot)));
  }

  return sid_certs;
}

QList<PKCS11_CERT *> QPkcs11::tokenCertsInSlot(PKCS11_SLOT *slot)
{
  QList<PKCS11_CERT *> pkcs11_certs;

  if (! moduleLoaded()) {
    return pkcs11_certs;
  }

  PKCS11_CERT *t_certs;
  unsigned int ncerts, m;

  if (! slot || slot->token == nullptr) {
    logMsg(QStringLiteral("No slot or token to parse certs from!"), QtWarningMsg);
    return pkcs11_certs;
  }

  const char *slot_dec(slot->description);
  const char *token_label(slot->token->label);

  if (PKCS11_enumerate_certs(slot->token, &t_certs, &ncerts) == -1) {
    //logMsg(QStringLiteral("No certs found for token '%1' in slot: %2").arg(token_label, slot_dec), QtDebugMsg);
    return pkcs11_certs;
  }

  if (ncerts <= 0) {
    logMsg(QStringLiteral("No certs returned from token '%1' in slot: %2").arg(token_label, slot_dec));
    return pkcs11_certs;
  }

  //logMsg(QStringLiteral("%1 cert(s) returned from token '%2' in slot: %3").arg(QString(ncerts), token_label, slot_dec), QtDebugMsg);

  for ( m = 0; m < ncerts; m++ ) {
    PKCS11_CERT *t_cert = t_certs + m;
    pkcs11_certs.append(t_cert);
  }

  return pkcs11_certs;
}

QPair<QString, QSslCertificate> QPkcs11::firstMatchingCertificate(
    const QString &sha1Match, bool clientOnly) // public
{
  QSslCertificate null_cert;
  QPair<QString, QSslCertificate> s_cert = qMakePair(QString(), null_cert);

  if (! moduleLoaded()) {
    return s_cert;
  }

  QPair<PKCS11_SLOT *, PKCS11_CERT *> p_cert = firstMatchingPkcs11Certificate(sha1Match, clientOnly);

  if (! p_cert.first || ! p_cert.second) {
    return s_cert;
  }

  s_cert = qMakePair(idForSlot(p_cert.first),
                     QSslCertificate(QByteArray_from_X509(p_cert.second->x509)));

  if (! sha1Match.isEmpty()) {
    logMsg(QStringLiteral("Found cert in token: %1").arg(p_cert.first->token->label), QtDebugMsg);
    logMsg(QStringLiteral("  matching SHA1: %1").arg(sha1Match), QtDebugMsg);
  }

  return s_cert;
}

QSslKey QPkcs11::certificatePrivateKey(const QString &sha1Match, bool clientOnly) // public
{
  QSslKey p_key;

  if (! moduleLoaded()) {
    return p_key;
  }

  QPair<PKCS11_SLOT *, PKCS11_CERT *> p_cert = firstMatchingPkcs11Certificate(sha1Match, clientOnly);

  if (! p_cert.first || ! p_cert.second) {
    logMsg(QStringLiteral("No matching cert for key with SHA1: %1").arg(sha1Match), QtWarningMsg);
    return p_key;
  }

  PKCS11_KEY *pkcs_key = PKCS11_find_key(p_cert.second);

  if (pkcs_key == nullptr) {
    logMsg(QStringLiteral("No matching key found for cert with SHA1: %1").arg(sha1Match), QtWarningMsg);
    return p_key;
  }

  logMsg(QStringLiteral("Found cert private key in token: %1").arg(p_cert.first->token->label), QtDebugMsg);
  logMsg(QStringLiteral("  matching cert SHA1: %1").arg(sha1Match), QtDebugMsg);

  // Populate EVP_PKEY cache, so cached QSslKey persists in QgsAuthMethod instance?
  // A cache may not be needed, since the key is populated into the active slot instance
  EVP_PKEY *evp_key = PKCS11_get_private_key(pkcs_key);
  if (evp_key == nullptr) {
    logMsg(QStringLiteral("Matching key's evp_key is null for cert with SHA1: %1").arg(sha1Match), QtWarningMsg);
    return p_key;
  }

  return QSslKey(Qt::HANDLE(evp_key), QSsl::PrivateKey);
}

const QString QPkcs11::dumpSlotInfo(PKCS11_SLOT *slot)
{
  QString msg;
  msg += QString("  slot manufacturer......: %1\n").arg(slot->manufacturer);
  msg += QString("  slot description.......: %1\n").arg(slot->description);
  msg += QString("  slot token label.......: %1\n").arg(slot->token->label);
  msg += QString("  slot token manufacturer: %1\n").arg(slot->token->manufacturer);
  msg += QString("  slot token model.......: %1\n").arg(slot->token->model);
  msg += QString("  slot token serialnr....: %1\n").arg(slot->token->serialnr);

  return msg;
}

void QPkcs11::dumpSlots(QList<PKCS11_SLOT *> t_slots)
{
  for (auto slot : t_slots) {
    dumpSlotInfo(slot);
  }
}

QPair<PKCS11_SLOT *, PKCS11_CERT *> QPkcs11::firstMatchingPkcs11Certificate(
    const QString &sha1Match, bool clientOnly)
{
  QPair<PKCS11_SLOT *, PKCS11_CERT *> s_cert = qMakePair(nullptr, nullptr);

  if (! moduleLoaded()) {
    return s_cert;
  }

  QMap<PKCS11_SLOT *, QList<PKCS11_CERT *> > s_certs = slotsWithTokenCerts(sha1Match, clientOnly);
  if (s_certs.isEmpty()) {
    logMsg(QStringLiteral("QPkcs11 did not find any slot certs with SHA1 of: %1").arg(sha1Match), QtWarningMsg);
    return s_cert;
  }

  QList<PKCS11_CERT *> p_certs = s_certs.first();
  if (p_certs.length() <= 0) {
    logMsg(QStringLiteral("QPkcs11 did not find any certs with SHA1 of: %1").arg(sha1Match), QtWarningMsg);
    return s_cert;
  }

  s_cert = qMakePair(s_certs.firstKey(), p_certs.first());

  return s_cert;
}

QSslCertificate QPkcs11::firstPkcs11QSslCertificate(PKCS11_CERT *pkcs11_cert)
{
  PKCS11_CERT * fist_cert = &pkcs11_cert[0];
  return QSslCertificate(QByteArray_from_X509(fist_cert->x509));
}

QList<QSslCertificate> QPkcs11::pkcs11QSslCertificates(QList<PKCS11_CERT *> pkcs11_certs)
{
  QSslCertificate cert;
  QList<QSslCertificate> certs;

  for (auto p_cert : pkcs11_certs) {
    cert = QSslCertificate(QByteArray_from_X509(p_cert->x509));
//    X509_free(p_cert->x509);
    certs.append(cert);
  }

  return certs;
}

QList<PKCS11_CERT *> QPkcs11::filterPkcs11Certificates(
    QList<PKCS11_CERT *> pkcs11_certs,
    const QString &sha1Match, bool clientOnly)
{
  Q_UNUSED(clientOnly)
  QList<PKCS11_CERT *> f_certs;

  for (auto p_cert : pkcs11_certs) {

    // TODO: Filter by clientOnly

    if (! sha1Match.isEmpty()) {
      //logMsg(QStringLiteral("SHA1 cert-matching for cert in slot"));
      if (shaHexForOpenSslCert(p_cert->x509).toLower() != sha1Match.toLower()) {
        continue;
      }
      //logMsg(QStringLiteral("Found SHA1 match!"));
      f_certs.append(p_cert);
    }

  }

  return f_certs;
}

QByteArray QPkcs11::QByteArray_from_X509(X509 *x509, QSsl::EncodingFormat format)
{
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

QString QPkcs11::getColonDelimited(const QString &txt)
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

QString QPkcs11::shaHexForCert(const QSslCertificate &cert, bool formatted)
{
  QString sha;

  if (cert.isNull()) {
    return sha;
  }

  sha = cert.digest( QCryptographicHash::Sha1 ).toHex();
  if ( formatted )
  {
    return getColonDelimited( sha );
  }
  return sha;
}

QString QPkcs11::shaHexForOpenSslCert(X509 *x509, bool formatted)
{
  QString sha;

  if (x509 == nullptr){
    return sha;
  }

  // Calculate SHA1 fingerprint
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int n;
  // digest = EVP_get_digestbyname("sha1");
  X509_digest(x509, EVP_sha1(), md, &n);

  // Culled from kf5/kdelibs4support/src/kssl/ksslcertificate.cpp
  sha = "";
  const char hv[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
  for (unsigned int j = 0; j < n; j++) {
    sha.append(QLatin1Char(hv[(md[j] & 0xf0) >> 4]));
    sha.append(QLatin1Char(hv[md[j] & 0x0f]));
  }

  if ( formatted )
  {
    return getColonDelimited( sha );
  }

  // Can't log to non-static msgLog
  //qDebug("SHA1 for OpenSSL cert: %s", qUtf8Printable(sha.toLower()));

  return sha;
}

//#include "qpkcs11.moc"
