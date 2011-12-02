/*
   Copyright 2005 Red Hat, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   In addition, as a special exception, Red Hat, Inc. gives permission
   to link the code of this program with the OpenSSL library (or with
   modified versions of OpenSSL that use the same license as OpenSSL),
   and distribute linked combinations including the two. You must obey
   the GNU General Public License in all respects for all of the code
   used other than OpenSSL. If you modify this file, you may extend
   this exception to your version of the file, but you are not
   obligated to do so. If you do not wish to do so, delete this
   exception statement from your version.

*/

/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape security libraries.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1994-2000
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Dr Vipul Gupta <vipul.gupta@sun.com>, Sun Microsystems Laboratories
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

/*
 * keyutil.c
 *
 * Command line utility for generating certificates and certificate signing requests.
 * It is invoked by crypto-utils' genkey when used in OpenSSL compatibility mode.
 *
 * Key generation, encryption, and certificate utility code based on
 * on code from NSS's security utilities and the certutil application.
 * Pem file key and certificate loading code based on code from the
 * NSS-enabled libcurl.
 * Elio Maldonado <emaldona@redhat.com>
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <unistd.h>
#include <sys/time.h>
#include <termios.h>

#include <prerror.h>
#include <secerr.h>

#include <nspr.h>
#include <nss.h>
#include <cert.h>
#include <certt.h>
#include <prio.h>
#include <prlong.h>
#include <prtime.h>
#include <pkcs11.h>
#include <pk11pub.h>
#include <pkcs11t.h>
#include <assert.h>
#include <secmod.h>
#include <base64.h>
#include <seccomon.h>
#include <secmodt.h>
#include <secoidt.h>
#include <keythi.h>
#include <keyhi.h>
#include <cryptohi.h>
#include <plarenas.h>
#include <secasn1.h>

#include <secpkcs5.h>
#include <keythi.h>
#include <secmodt.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>

#include "keyutil.h"
#include "secutil.h"

#define MIN_KEY_BITS        512
/* MAX_KEY_BITS should agree with MAX_RSA_MODULUS in freebl */
#define MAX_KEY_BITS        8192
#define DEFAULT_KEY_BITS    1024

#define SEC_CT_PRIVATE_KEY      "private-key"
#define SEC_CT_PUBLIC_KEY       "public-key"
#define SEC_CT_CERTIFICATE      "certificate"
#define SEC_CT_CERTIFICATE_REQUEST  "certificate-request"
#define SEC_CT_PKCS7            "pkcs7"
#define SEC_CT_CRL          "crl"

#define NS_CERTREQ_HEADER "-----BEGIN NEW CERTIFICATE REQUEST-----"
#define NS_CERTREQ_TRAILER "-----END NEW CERTIFICATE REQUEST-----"

#define NS_CERT_HEADER "-----BEGIN CERTIFICATE-----"
#define NS_CERT_TRAILER "-----END CERTIFICATE-----"

#define NS_CRL_HEADER  "-----BEGIN CRL-----"
#define NS_CRL_TRAILER "-----END CRL-----"

#define KEY_HEADER  "-----BEGIN PRIVATE KEY-----"
#define KEY_TRAILER "-----END PRIVATE KEY-----"

#define ENCRYPTED_KEY_HEADER  "-----BEGIN ENCRYPTED PRIVATE KEY-----"
#define ENCRYPTED_KEY_TRAILER "-----END ENCRYPTED PRIVATE KEY-----"

#define REP_MECHANISM mechanism[testId/2/2%46]

#define NUM_KEYSTROKES 120
#define RAND_BUF_SIZE 60

#define ERROR_BREAK rv = SECFailure;break;

#define GEN_BREAK(e) rv=e; break;

struct tuple_str {
    PRErrorCode  errNum;
    const char * errString;
};

typedef struct tuple_str tuple_str;

#define ER2(a,b)   {a, b},
#define ER3(a,b,c) {a, c},

#include "secerr.h"
#include "sslerr.h"

#ifndef PK11_SETATTRS
#define PK11_SETATTRS(x,id,v,l) (x)->type = (id); \
		(x)->pValue=(v); (x)->ulValueLen = (l);
#endif

SECMODModule* mod = NULL; /* the pem module */
static const char* pem_library = "libnsspem.so";
/* will use this slot only */
CK_SLOT_ID slotID = 1;

char *progName;

static const struct option options[] = {
    { "command",    required_argument, NULL, 'c' },
    { "renew",      required_argument, NULL, 'r' },
    { "subject",    required_argument, NULL, 's' },
    { "gkeysize",   required_argument, NULL, 'g' },
    { "validity",   required_argument, NULL, 'v' },
    { "encpwd",     required_argument, NULL, 'e' },
    { "filepwdnss", required_argument, NULL, 'f' },
    { "digest",     required_argument, NULL, 'd' },
    { "znoisefile", required_argument, NULL, 'z' },
    { "input",      required_argument, NULL, 'i' }, /* key in */
    { "passout",    required_argument, NULL, 'p' },
    { "output",     required_argument, NULL, 'o' }, /* reg, cert, enckey */
    { "keyout",     required_argument, NULL, 'k' }, /* plaintext key */
    { "ascii",      no_argument,       NULL, 'a' }, /* ascii */
    { "cacert",     no_argument,       NULL, 't' }, /* ca cert renewal */
    { "help",       no_argument,       NULL, 'h' },
    { NULL }
};

static certutilExtnList keyutil_extns;

static void
Usage(char *progName)
{
    fprintf(stderr, "Usage: %s [options] arguments\n", progName);
    fprintf(stderr, "{-c|--command} command, one of [genreq|makecert]");
    fprintf(stderr, "{-r|--renew} cert-to-renew     the file with the certifificast to renew");
    fprintf(stderr, "{-s|--subject} subject         subject distinguished name");
    fprintf(stderr, "{-g|--gsize} key_size          size in bitsof the rsa key to generate");
    fprintf(stderr, "{-v|--validity} months         cert validity in months");
    fprintf(stderr, "{-z|--znoisefile} noisefile    seed file for use in key gneration");
    fprintf(stderr, "{-e|--encpwd} keypwd           key encryption_password");
    fprintf(stderr, "{-f|--filepwdnss} modpwdfile   file with the module access_password");
    fprintf(stderr, "{-d|--digest} digest-algorithm digest algorithm");
    fprintf(stderr, "{-i|--input} inputkey-file     file with key with which to encrypt or to sign a request");
    fprintf(stderr, "{-p|--passout} pbe-password    the password for encrypting of the key");
    fprintf(stderr, "{-o|--output} out-file         output file for a csr or cert");
    fprintf(stderr, "{-k|--keyfile} out-key-file    output key file, with csr or certgen");
    fprintf(stderr, "{-t|--cacert}                  indicates that cert renewal is for a ca");
    fprintf(stderr, "{-h|--help}                    print this help message");
    fprintf(stderr, "\n");
    exit(1);
}

/*
 * Authenticates to any token that may require it.
 * It also checks that the NSS database ahs been initialized.
 * This function is modeled after the one in libcurl.
 */
static SECStatus nss_Init_Tokens(secuPWData *pwdata)
{
    PK11SlotList *slotList;
    PK11SlotListElement *listEntry;
    SECStatus ret, status = SECSuccess;

    PK11_SetPasswordFunc(SECU_GetModulePassword);

    /* List all currently available tokens and traverse
     * the list authenticating to them
     */
    slotList = PK11_GetAllTokens(CKM_INVALID_MECHANISM, PR_FALSE, PR_TRUE, NULL);

    for (listEntry = PK11_GetFirstSafe(slotList);
         listEntry; listEntry = listEntry->next) {

        PK11SlotInfo *slot = listEntry->slot;

        if (PK11_NeedLogin(slot) && PK11_NeedUserInit(slot)) {
            if (slot == PK11_GetInternalKeySlot()) {
                SECU_PrintError(progName ? progName : "keyutil",
                    "The NSS database has not been initialized\n");
            } else {
            	SECU_PrintError(progName,
                    "The token %s has not been initialized",
                    PK11_GetTokenName(slot));
            }
            PK11_FreeSlot(slot);
            continue;
        }

        ret = PK11_Authenticate(slot, PR_TRUE, &pwdata);
        if (SECSuccess != ret) {
            if (PR_GetError() == SEC_ERROR_BAD_PASSWORD) {
        	    SECU_PrintError(progName ? progName : "keyutil",
        	    "%s: The password for token '%s' is incorrect\n",
        	    PK11_GetTokenName(slot));
            }
            status = SECFailure;
            break;
        }
        PK11_FreeSlot(slot);
    }

    return status;
}

/*
 * Loads the cert from the specified file into the module at
 * the specified slot.
 *
 * This function is modelled after the one in libcurl.
 *
 * @param slot the slot to load the cert into
 * @param cacert true if the cert is for a ca, false otherwise
 * @param certfile pem encoded file with the certificate
 * @param nickname the certificate niskanme
 */
static SECStatus loadCert(
    PK11SlotInfo *slot,
    PRBool cacert,
    const char *certfile,
    const char *nickname)
{
    SECStatus rv = SECSuccess;
    PK11GenericObject *genericObjCert;
    CK_ATTRIBUTE theCertTemplate[20];
    CK_ATTRIBUTE *attrs = NULL;
    CK_BBOOL cktrue = CK_TRUE;
    CK_BBOOL ckfalse = CK_FALSE;
    CK_OBJECT_CLASS certObjClass = CKO_CERTIFICATE;
    CERTCertificate *cert = NULL;

    do {
        /*
         * Load the certificate
         */
        attrs = theCertTemplate;
        PK11_SETATTRS(attrs, CKA_CLASS, &certObjClass, sizeof(certObjClass)); attrs++;
        PK11_SETATTRS(attrs, CKA_TOKEN, &cktrue, sizeof(CK_BBOOL)); attrs++;
        PK11_SETATTRS(attrs, CKA_LABEL, (unsigned char *)certfile, strlen(certfile)+1); attrs++;
        if (cacert) {
            PK11_SETATTRS(attrs, CKA_TRUST, &cktrue, sizeof(CK_BBOOL) ); attrs++;
        } else {
            PK11_SETATTRS(attrs, CKA_TRUST, &ckfalse, sizeof(CK_BBOOL) ); attrs++;
        }

        /* Load the certificate in our PEM module into the appropriate slot. */
        genericObjCert = PK11_CreateGenericObject(slot, theCertTemplate, 4, PR_FALSE /* isPerm */);
        if (!genericObjCert) {
            rv = PR_GetError();
            SECU_PrintError(progName,
                "Unable to create object for cert, (%s)", SECU_Strerror(rv));
            break;
        }
        if (!cacert) {
            /* Double-check that the certificate or nickname requested exists in
             * either the token or the NSS certificate database.
             */
            cert = PK11_FindCertFromNickname((char *)nickname, NULL);
            if (!cert) {
            	SECU_PrintError(progName ? progName : "keyutil",
                    "%s: Can't find cert named (%s), bailing out\n", nickname);
                rv = 255;
        	    break;
        	} else {
        	   rv = SECSuccess;
        	}
        } else {
        	rv = SECSuccess;
        }

    } while (0);

    if (cert)
        CERT_DestroyCertificate(cert);

    return rv;
}

/*
 * Loads the key from the specified file into the module at
 * the specified slot.
 *
 * function is modelled after the one in libcurl.
 * @param slot the slot into which the key will be loaded
 * @param keyfile the file from which the key will be read
 * @param nickname the nickname of the matching certificate
 */
static SECStatus loadKey(
    PK11SlotInfo *slot,
    const char *keyfile,
    const char *nickname,
    secuPWData *pwdata)
{
	SECStatus rv = SECSuccess;
    CK_ATTRIBUTE *attrs = NULL;
    CK_BBOOL cktrue = CK_TRUE;
	PRBool isPresent;
    PK11GenericObject *object;
    CK_ATTRIBUTE theTemplate[20];
    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CERTCertificate *cert = NULL;
    SECKEYPrivateKey *privkey = NULL;

    do {
        attrs = theTemplate;
        PK11_SETATTRS(attrs, CKA_CLASS, &objClass, sizeof(objClass) ); attrs++;
        PK11_SETATTRS(attrs, CKA_TOKEN, &cktrue, sizeof(CK_BBOOL) ); attrs++;
        PK11_SETATTRS(attrs, CKA_LABEL, (unsigned char *)keyfile, strlen(keyfile)+1); attrs++;

        /* When adding an encrypted key the PKCS#11 will be set as removed */
        object = PK11_CreateGenericObject(slot, theTemplate, 3, PR_FALSE /* isPerm */);
        if (!object) {
            rv = SEC_ERROR_BAD_KEY;
            PR_SetError(rv, 0);
            SECU_PrintError(progName ? progName : "keyutil",
                "Unable to create key object (%s)\n", SECU_Strerror(rv));
            break;
        }

        /* This will force the token to be seen as re-inserted */
        (void) SECMOD_WaitForAnyTokenEvent(mod, 0, 0);
        isPresent = PK11_IsPresent(slot);
        assert(isPresent);

        rv = PK11_Authenticate(slot, PR_TRUE, pwdata);
        if (rv != SECSuccess) {
            SECU_PrintError(progName ? progName : "keyutil",
                "Can't authenticate\n", SECU_Strerror(rv));
            break;
        }

        /* must find it again because "reinsertion" */
        cert = PK11_FindCertFromNickname((char *)nickname, NULL);
        assert(cert);

        /* Can we find the key? */

        privkey = PK11_FindPrivateKeyFromCert(slot, cert, pwdata);
        if (!privkey) {
            rv = PR_GetError();
            SECU_PrintError(progName ? progName : "keyutil",
                "Unable to find the key for cert, (%s)\n", SECU_Strerror(rv));
            GEN_BREAK(SECFailure);
        }
        rv = SECSuccess;

    } while (0);

    if (cert)
        CERT_DestroyCertificate(cert);

    return rv;
}

/*
 * Loads the certificate and private key from the specified files into
 * the PEM the module at the specified slot.
 *
 * @param slot the slot to load into
 * @param certfile the certificate file
 * @param nickname the certificate nickname
 * @param keyfile the key file
 * @param pwdata access password
 */
static SECStatus
loadCertAndKey(
    PK11SlotInfo *slot,
    PRBool cacert,
    const char *certfile,
    const char *nickname,
    const char *keyfile,
    secuPWData *pwdata)
{
    SECStatus rv = SECSuccess;

    /*
     * Load the certificate first
     */
    rv = loadCert(slot, cacert, certfile, nickname);
    if (rv != SECSuccess) return rv;

    /*
     * Load the private key next
     */
    rv = loadKey(slot, keyfile, nickname, pwdata);

    return rv;
}

/*
 * Extract the public and private keys and the subject
 * distinguished from the cert with the given nickname
 * in the given slot.
 *
 * @param nickname the certificate nickname
 * @param slot the slot where keys it was loaded
 * @param pwdat module authentication password
 * @param privkey private key out
 * @param pubkey public key out
 * @param subject subject out
 */
static SECStatus extractRSAKeysAndSubject(
	const char *nickname,
	PK11SlotInfo *slot,
	secuPWData *pwdata,
    SECKEYPrivateKey **privkey,
    SECKEYPublicKey **pubkey,
    CERTName **subject)
{
    SECStatus rv = SECSuccess;
    CERTCertificate *cert = NULL;

    do {
        cert = PK11_FindCertFromNickname((char *)nickname, NULL);
        if (!cert) {
            GEN_BREAK(SECFailure);
        }

        *pubkey = CERT_ExtractPublicKey(cert);
        if (!*pubkey) {
            SECU_PrintError(progName,
                "Could not get public key from cert, (%s)\n",
                SECU_Strerror(PR_GetError()));
            GEN_BREAK(SECFailure);
        }

        *privkey = PK11_FindKeyByDERCert(slot, cert, pwdata);
        if (!*privkey) {
            rv = PR_GetError();
            SECU_PrintError(progName,
                "Unable to find the key with PK11_FindKeyByDERCert, (%s)\n",
                SECU_Strerror(rv));
            *privkey= PK11_FindKeyByAnyCert(cert, &pwdata);
            rv = PR_GetError();
            SECU_PrintError(progName,
                "Unable to find the key with PK11_FindKeyByAnyCert, (%s)\n",
                SECU_Strerror(rv));
            GEN_BREAK(SECFailure);
        }

        assert(((*privkey)->keyType) == rsaKey);
        *subject = CERT_AsciiToName(cert->subjectName);

        if (!*subject) {
            SECU_PrintError(progName,
                "Improperly formatted name: \"%s\"\n",
                cert->subjectName);
            GEN_BREAK(SECFailure);
        }
        rv = SECSuccess;
    } while (0);

    if (cert)
        CERT_DestroyCertificate(cert);
    return rv;
}

/*
 * GetCertRequest, CertReq, MakeV1Cert, SignCert, and CreateCert
 * are modeled after the corresponding ones in certutil.
 */

static CERTCertificateRequest *
GetCertRequest(PRFileDesc *inFile, PRBool ascii)
{
    CERTCertificateRequest *certReq = NULL;
    CERTSignedData signedData;
    PRArenaPool *arena = NULL;
    SECItem reqDER;
    SECStatus rv;

    reqDER.data = NULL;
    do {
        arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
        if (arena == NULL) {
            GEN_BREAK(SECFailure);
        }

        rv = SECU_ReadDERFromFile(&reqDER, inFile, ascii);
        if (rv) {
        	GEN_BREAK(rv);
        }
        certReq = (CERTCertificateRequest*) PORT_ArenaZAlloc
          (arena, sizeof(CERTCertificateRequest));
        if (!certReq) {
            GEN_BREAK(SECFailure);
        }
        certReq->arena = arena;

        /* Since cert request is a signed data, must decode to get the inner
           data
         */
        PORT_Memset(&signedData, 0, sizeof(signedData));
        rv = SEC_ASN1DecodeItem(arena, &signedData,
            SEC_ASN1_GET(CERT_SignedDataTemplate), &reqDER);
        if (rv) {
            GEN_BREAK(rv);
        }
        rv = SEC_ASN1DecodeItem(arena, certReq,
                SEC_ASN1_GET(CERT_CertificateRequestTemplate), &signedData.data);
        if (rv) {
            GEN_BREAK(rv);
        }
        rv = CERT_VerifySignedDataWithPublicKeyInfo(&signedData,
                &certReq->subjectPublicKeyInfo, NULL /* wincx */);
    } while (0);

    if (reqDER.data) {
        SECITEM_FreeItem(&reqDER, PR_FALSE);
    }

    if (rv) {
        SECU_PrintError(progName, "bad certificate request\n");
        if (arena) {
            PORT_FreeArena(arena, PR_FALSE);
        }
        certReq = NULL;
    }

    return certReq;
}

static SECStatus
CertReq(SECKEYPrivateKey *privk, SECKEYPublicKey *pubk, KeyType keyType,
        SECOidTag hashAlgTag, CERTName *subject, char *phone, int ascii,
        const char *emailAddrs, const char *dnsNames,
        certutilExtnList extnList,
        PRFileDesc *outFile)
{
    CERTSubjectPublicKeyInfo *spki;
    CERTCertificateRequest *cr;
    SECItem *encoding;
    SECOidTag signAlgTag;
    SECItem result;
    SECStatus rv;
    PRArenaPool *arena;
    PRInt32 numBytes;
    void *extHandle;

    /* Create info about public key */
    spki = SECKEY_CreateSubjectPublicKeyInfo(pubk);
    if (!spki) {
        SECU_PrintError(progName, "unable to create subject public key");
        return SECFailure;
    }

    /* Generate certificate request */
    cr = CERT_CreateCertificateRequest(subject, spki, NULL);
    if (!cr) {
        SECU_PrintError(progName, "unable to make certificate request");
        return SECFailure;
    }

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if ( !arena ) {
        SECU_PrintError(progName, "out of memory");
        return SECFailure;
    }

    extHandle = CERT_StartCertificateRequestAttributes(cr);
    if (extHandle == NULL) {
        PORT_FreeArena (arena, PR_FALSE);
        return SECFailure;
    }
    if (AddExtensions(extHandle, emailAddrs, dnsNames, extnList)
                  != SECSuccess) {
        PORT_FreeArena (arena, PR_FALSE);
        return SECFailure;
    }
    CERT_FinishExtensions(extHandle);
    CERT_FinishCertificateRequestAttributes(cr);

    /* Der encode the request */
    encoding = SEC_ASN1EncodeItem(arena, NULL, cr,
                                  SEC_ASN1_GET(CERT_CertificateRequestTemplate));
    if (encoding == NULL) {
        SECU_PrintError(progName, "der encoding of request failed");
        return SECFailure;
    }

    /* Sign the request */
    signAlgTag = SEC_GetSignatureAlgorithmOidTag(keyType, hashAlgTag);
    if (signAlgTag == SEC_OID_UNKNOWN) {
        SECU_PrintError(progName, "unknown Key or Hash type");
        return SECFailure;
    }
    rv = SEC_DerSignData(arena, &result, encoding->data, encoding->len,
             privk, signAlgTag);
    if (rv) {
        SECU_PrintError(progName, "signing of data failed");
        return SECFailure;
    }

    /* Encode request in specified format */
    if (ascii) {
        char *obuf;
        char *name, *email, *org, *state, *country;
        SECItem *it;
        int total;

        it = &result;

        obuf = BTOA_ConvertItemToAscii(it);
        total = PL_strlen(obuf);

        name = CERT_GetCommonName(subject);
        if (!name) {
            name = strdup("(not specified)");
        }

        if (!phone)
            phone = strdup("(not specified)");

        email = CERT_GetCertEmailAddress(subject);
        if (!email)
            email = strdup("(not specified)");

        org = CERT_GetOrgName(subject);
        if (!org)
            org = strdup("(not specified)");

        state = CERT_GetStateName(subject);
        if (!state)
            state = strdup("(not specified)");

	    country = CERT_GetCountryName(subject);
	    if (!country)
	        country = strdup("(not specified)");

	    PR_fprintf(outFile, "%s\n", NS_CERTREQ_HEADER);
	    numBytes = PR_Write(outFile, obuf, total);
	    if (numBytes != total) {
	        SECU_PrintSystemError(progName, "write error");
	        return SECFailure;
	    }
	    PR_fprintf(outFile, "\n%s\n", NS_CERTREQ_TRAILER);
	} else {
	    numBytes = PR_Write(outFile, result.data, result.len);
	    if (numBytes != (int)result.len) {
	        SECU_PrintSystemError(progName, "write error");
	        return SECFailure;
	    }
    }
    return SECSuccess;
}

static CERTCertificate *
MakeV1Cert(CERTCertDBHandle *handle,
        CERTCertificateRequest *req,
        char *issuerNickName,
        PRBool selfsign,
        unsigned int serialNumber,
        int warpmonths,
        int validityMonths)
{
    CERTCertificate *issuerCert = NULL;
    CERTValidity *validity;
    CERTCertificate *cert = NULL;
    PRExplodedTime printableTime;
    PRTime now, after;

    if ( !selfsign ) {
        issuerCert = CERT_FindCertByNicknameOrEmailAddr(handle, issuerNickName);
        if (!issuerCert) {
            SECU_PrintError(progName, "could not find certificate named \"%s\"",
                issuerNickName);
            return NULL;
        }
    }

    now = PR_Now();
    PR_ExplodeTime (now, PR_GMTParameters, &printableTime);
	if ( warpmonths ) {
	    printableTime.tm_month += warpmonths;
	    now = PR_ImplodeTime (&printableTime);
	    PR_ExplodeTime (now, PR_GMTParameters, &printableTime);
	}
    printableTime.tm_month += validityMonths;
    after = PR_ImplodeTime (&printableTime);

    /* note that the time is now in micro-second unit */
    validity = CERT_CreateValidity (now, after);
    if (validity) {
        cert = CERT_CreateCertificate(serialNumber,
                      (selfsign ? &req->subject
                                : &issuerCert->subject),
                                  validity, req);

        CERT_DestroyValidity(validity);
    }
    if ( issuerCert ) {
        CERT_DestroyCertificate (issuerCert);
    }

    return(cert);
}

static SECItem *
SignCert(CERTCertDBHandle *handle, CERTCertificate *cert, PRBool selfsign,
         SECOidTag hashAlgTag,
         SECKEYPrivateKey *privKey, char *issuerNickName, void *pwarg)
{
    SECItem der;
    SECItem *result = NULL;
    SECKEYPrivateKey *caPrivateKey = NULL;
    SECStatus rv;
    PRArenaPool *arena;
    SECOidTag algID;
    void *dummy;

    if ( !selfsign ) {
        CERTCertificate *issuer = PK11_FindCertFromNickname(issuerNickName, pwarg);
        if ( (CERTCertificate *)NULL == issuer ) {
            SECU_PrintError(progName, "unable to find issuer with nickname %s",
                    issuerNickName);
            return (SECItem *)NULL;
        }

        privKey = caPrivateKey = PK11_FindKeyByAnyCert(issuer, pwarg);
        CERT_DestroyCertificate(issuer);
        if (caPrivateKey == NULL) {
            SECU_PrintError(progName, "unable to retrieve key %s", issuerNickName);
            return NULL;
        }
    }

    arena = cert->arena;

    algID = SEC_GetSignatureAlgorithmOidTag(privKey->keyType, hashAlgTag);
    if (algID == SEC_OID_UNKNOWN) {
    	SECU_PrintError(progName, "Unknown key or hash type for issuer.");
        goto done;
    }

    rv = SECOID_SetAlgorithmID(arena, &cert->signature, algID, 0);
    if (rv != SECSuccess) {
    	SECU_PrintError(progName, "Could not set signature algorithm id.");
        goto done;
    }

    /* we only deal with cert v3 here */
    *(cert->version.data) = 2;
    cert->version.len = 1;

    der.len = 0;
    der.data = NULL;
    dummy = SEC_ASN1EncodeItem (arena, &der, cert,
                SEC_ASN1_GET(CERT_CertificateTemplate));
    if (!dummy) {
    	SECU_PrintError(progName, "Could not encode certificate.\n");
        goto done;
    }

    result = (SECItem *) PORT_ArenaZAlloc (arena, sizeof (SECItem));
    if (result == NULL) {
    	SECU_PrintError(progName, "Could not allocate item for certificate data.\n");
        goto done;
    }

    rv = SEC_DerSignData(arena, result, der.data, der.len, privKey, algID);
    if (rv != SECSuccess) {
	    fprintf (stderr, "Could not sign encoded certificate data.\n");
	    /* result allocated out of the arena, it will be freed
	     * when the arena is freed */
	    result = NULL;
	    goto done;
    }
    cert->derCert = *result;
done:
    if (caPrivateKey) {
    SECKEY_DestroyPrivateKey(caPrivateKey);
    }
    return result;
}

static SECStatus
CreateCert(
    CERTCertDBHandle *handle,
    char             *issuerNickName,
    PRFileDesc       *inFile,
    PRFileDesc       *outFile,
    SECKEYPrivateKey *selfsignprivkey,
    void             *pwarg,
    SECOidTag        hashAlgTag,
    unsigned int     serialNumber,
    int              warpmonths,
    int              validityMonths,
    const char       *emailAddrs,
    const char       *dnsNames,
    PRBool           ascii,
    PRBool           selfsign,
    certutilExtnList extnList,
    CERTCertificate  **outCert)
{
    void                   *extHandle;
    SECItem                *certDER;
    PRArenaPool            *arena           = NULL;
    SECItem                reqDER;
    CERTCertExtension      **CRexts;
    CERTCertificate        *subjectCert     = NULL;
    CERTCertificateRequest *certReq         = NULL;
    SECStatus               rv              = SECSuccess;

    reqDER.data = NULL;
    do {
        arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
        if (!arena) {
            GEN_BREAK (SECFailure);
        }

        /* Create a certrequest object from the input cert request der */
        certReq = GetCertRequest(inFile, ascii);
        if (certReq == NULL) {
            GEN_BREAK (SECFailure)
        }

        subjectCert = MakeV1Cert (handle, certReq, issuerNickName, selfsign,
                  serialNumber, warpmonths, validityMonths);
        if (subjectCert == NULL) {
            GEN_BREAK (SECFailure)
        }

        extHandle = CERT_StartCertExtensions (subjectCert);
        if (extHandle == NULL) {
            GEN_BREAK (SECFailure)
        }

        rv = AddExtensions(extHandle, emailAddrs, dnsNames, extnList);
        if (rv != SECSuccess) {
            GEN_BREAK (SECFailure)
        }

        if (certReq->attributes != NULL &&
            certReq->attributes[0] != NULL &&
            certReq->attributes[0]->attrType.data != NULL &&
            certReq->attributes[0]->attrType.len   > 0    &&
            SECOID_FindOIDTag(&certReq->attributes[0]->attrType)
                == SEC_OID_PKCS9_EXTENSION_REQUEST) {
            rv = CERT_GetCertificateRequestExtensions(certReq, &CRexts);
            if (rv != SECSuccess)
                break;
            rv = CERT_MergeExtensions(extHandle, CRexts);
            if (rv != SECSuccess)
                break;
        }

        CERT_FinishExtensions(extHandle);

        certDER = SignCert(handle, subjectCert, selfsign, hashAlgTag,
                       selfsignprivkey, issuerNickName,pwarg);

        if (certDER) {
            if (ascii) {
                PR_fprintf(outFile, "%s\n%s\n%s\n", NS_CERT_HEADER,
                    BTOA_DataToAscii(certDER->data, certDER->len),
                    NS_CERT_TRAILER);
            } else {
                PR_Write(outFile, certDER->data, certDER->len);
           }
        }

    } while (0);

    CERT_DestroyCertificateRequest(certReq);
    PORT_FreeArena (arena, PR_FALSE);
    if (rv == SECSuccess) {
        PR_fprintf(PR_STDOUT, "%s Copying the cert pointer\n", progName);
        *outCert = subjectCert;
    } else {
        PRErrorCode  perr = PR_GetError();
        SECU_PrintError(progName, "Unable to create cert, (%s)\n", SECU_Strerror(perr));
        if (subjectCert)
            CERT_DestroyCertificate (subjectCert);
    }

    return (rv);
}


typedef struct KeyPairStr KeyPair;

typedef struct _PrivateKeyStr PrivateKey;


/*  Keyutil commands  */
typedef enum _CommandType {
    cmd_CertReq,
    cmd_CreateNewCert
} CommandType;

/* returns 0 for success, -1 for failure (EOF encountered) */
static int
UpdateRNG(void)
{
    char           randbuf[RAND_BUF_SIZE];
    int            fd,  count;
    int            c;
    int            rv       = 0;
    cc_t           orig_cc_min;
    cc_t           orig_cc_time;
    tcflag_t       orig_lflag;
    struct termios tio;
    char meter[] = {
      "\r|                                                            |" };

#define FPS fprintf(stderr,
    FPS "\n");
    FPS "A random seed must be generated that will be used in the\n");
    FPS "creation of your key.  One of the easiest ways to create a\n");
    FPS "random seed is to use the timing of keystrokes on a keyboard.\n");
    FPS "\n");
    FPS "To begin, type keys on the keyboard until this progress meter\n");
    FPS "is full.  DO NOT USE THE AUTOREPEAT FUNCTION ON YOUR KEYBOARD!\n");
    FPS "\n");
    FPS "\n");
    FPS "Continue typing until the progress meter is full:\n\n");
    FPS meter);
    FPS "\r|");

    /* turn off echo on stdin & return on 1 char instead of NL */
    fd = fileno(stdin);

    tcgetattr(fd, &tio);
    orig_lflag = tio.c_lflag;
    orig_cc_min = tio.c_cc[VMIN];
    orig_cc_time = tio.c_cc[VTIME];
    tio.c_lflag &= ~ECHO;
    tio.c_lflag &= ~ICANON;
    tio.c_cc[VMIN] = 1;
    tio.c_cc[VTIME] = 0;
    tcsetattr(fd, TCSAFLUSH, &tio);

    /* Get random noise from keyboard strokes */
    count = 0;
    while (count < sizeof randbuf) {
    c = getc(stdin);
    if (c == EOF) {
        rv = -1;
        break;
    }
    randbuf[count] = c;
    if (count == 0 || c != randbuf[count-1]) {
        count++;
        FPS "*");
    }
    }
    PK11_RandomUpdate(randbuf, sizeof randbuf);
    memset(randbuf, 0, sizeof randbuf);

    FPS "\n\n");
    FPS "Finished.  Press enter to continue: ");

    while ((c = getc(stdin)) != '\n' && c != EOF)
        ;
    if (c == EOF)
    rv = -1;
    FPS "\n");

#undef FPS

    /* set back termio the way it was */
    tio.c_lflag = orig_lflag;
    tio.c_cc[VMIN] = orig_cc_min;
    tio.c_cc[VTIME] = orig_cc_time;
    tcsetattr(fd, TCSAFLUSH, &tio);

    return rv;
}

static SECStatus
CERTUTIL_FileForRNG(const char *noise)
{
    char buf[2048];
    PRFileDesc *fd;
    PRInt32 count;

    fd = PR_Open(noise,PR_RDONLY,0);
    if (!fd) {
    SECU_PrintError(progName, "Failed to open noise file %s\n", noise);
    return SECFailure;
    }

    do {
    count = PR_Read(fd,buf,sizeof(buf));
    if (count > 0) {
        PK11_RandomUpdate(buf,count);
    }
    } while (count > 0);

    PR_Close(fd);
    return SECSuccess;
}

SECKEYPrivateKey *
GenerateRSAPrivateKey(KeyType keytype,
    PK11SlotInfo *slot,
    int rsasize,
    int publicExponent,
    char *noise,
    SECKEYPublicKey **pubkeyp,
    secuPWData *pwdata)
{
    CK_MECHANISM_TYPE  mechanism;
    PK11RSAGenParams   rsaparams;
    SECKEYPrivateKey * privKey = NULL;

    if (slot == NULL)
        return NULL;

    if (PK11_Authenticate(slot, PR_TRUE, pwdata) != SECSuccess)
        return NULL;

    /*
     * Do some random-number initialization.
     */

    if (noise) {
        SECStatus rv = CERTUTIL_FileForRNG(noise);
        if (rv != SECSuccess) {
            PORT_SetError(PR_END_OF_FILE_ERROR); /* XXX */
            return NULL;
        }
    } else {
        int rv = UpdateRNG();
        if (rv) {
            PORT_SetError(PR_END_OF_FILE_ERROR);
            return NULL;
        }
    }

    rsaparams.keySizeInBits = rsasize;
    rsaparams.pe = publicExponent;
    mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;

    fprintf(stderr, "\n\n");
    fprintf(stderr, "Generating key. This may take a few moments...\n\n");

    privKey = PK11_GenerateKeyPair(slot,
            mechanism, &rsaparams, pubkeyp,
            PR_FALSE /* isPerm */,
            PR_TRUE  /* isSensitive*/,
            pwdata   /* wincx */
            );

    assert(privKey);
    assert(pubkeyp);
    return privKey;
}

/*
 * Decrypt the private key
 */
SECStatus DecryptKey(
    SECKEYEncryptedPrivateKeyInfo *epki,
    SECOidTag algTag,
    SECItem *pwitem,
    secuPWData *pwdata,
    SECItem *derPKI)
{
    SECItem  *cryptoParam = NULL;
    PK11SymKey *symKey = NULL;
    PK11Context *ctx = NULL;
    SECStatus rv = SECSuccess;

    if (!pwitem) {
        return SEC_ERROR_INVALID_ARGS;
    }

    do {
        SECAlgorithmID algid = epki->algorithm;
        CK_MECHANISM_TYPE cryptoMechType;
        CK_MECHANISM cryptoMech;
        CK_ATTRIBUTE_TYPE operation = CKA_DECRYPT;
        PK11SlotInfo *slot = NULL;

        cryptoMechType = PK11_GetPBECryptoMechanism(&algid, &cryptoParam, pwitem);
        if (cryptoMechType == CKM_INVALID_MECHANISM)  {
            ERROR_BREAK;
        }

        cryptoMech.mechanism = PK11_GetPadMechanism(cryptoMechType);
        cryptoMech.pParameter = cryptoParam ? cryptoParam->data : NULL;
        cryptoMech.ulParameterLen = cryptoParam ? cryptoParam->len : 0;

        slot = PK11_GetBestSlot(cryptoMechType, NULL);
        if (!slot) {
        	ERROR_BREAK;
        }

        symKey = PK11_PBEKeyGen(slot, &algid, pwitem, PR_FALSE, pwdata);
        if (symKey == NULL) {
            ERROR_BREAK;
        }

        ctx = PK11_CreateContextBySymKey(cryptoMechType, operation, symKey, cryptoParam);
        if (ctx == NULL) {
             ERROR_BREAK;
        }

        rv = PK11_CipherOp(ctx,
        		derPKI->data,                  /* out     */
                (int *)(&derPKI->len),         /* out len */
                (int)epki->encryptedData.len,  /* max out */
                epki->encryptedData.data,      /* in      */
                (int)epki->encryptedData.len); /* in len  */

        assert(derPKI->len == epki->encryptedData.len);
        assert(rv == SECSuccess);
        rv = PK11_Finalize(ctx);
        assert(rv == SECSuccess);

    } while (0);

    /* cleanup */
    if (symKey) {
        PK11_FreeSymKey(symKey);
    }
    if (cryptoParam) {
        SECITEM_ZfreeItem(cryptoParam, PR_TRUE);
        cryptoParam = NULL;
    }
    if (ctx) {
        PK11_DestroyContext(ctx, PR_TRUE);
    }

    return rv;

}

/* Output the private key to a file */
static SECStatus
KeyOut(const char *keyoutfile,
       const char *keyEncPwd,
       SECKEYPrivateKey *privkey,
       SECKEYPublicKey *pubkey,
       SECOidTag algTag,
       secuPWData *pwdata,
       PRBool ascii)
{

#define RAND_PASS_LEN 6

    PRFileDesc *keyOutFile = NULL;
    PRUint32 total = 0;
    PRUint32 numBytes = 0;
    SECItem *encryptedKeyDER = NULL;
    SECItem clearKeyDER = { 0, NULL, 0 };
    SECItem pwitem = { 0, NULL, 0 };
    PRArenaPool *arenaForEPKI = NULL;
    PLArenaPool *arenaForPKI = NULL;
    SECKEYEncryptedPrivateKeyInfo *epki = NULL;
    unsigned char randomPassword[RAND_PASS_LEN];

    int rv = SECSuccess;

    do {
        /* Caller wants an encrypted key. */
        if (keyEncPwd) {
            pwitem.data = (unsigned char *) PORT_Strdup((char*)keyEncPwd);
            pwitem.len = (unsigned int) strlen((char*)keyEncPwd);
            pwitem.type = siBuffer;
        } else {
            /* Caller wants clear keys. Make up a dummy
             * password to get NSS to export an encrypted
             * key which we will decrypt.
             */
            rv = PK11_GenerateRandom(randomPassword, RAND_PASS_LEN);
            if (rv != SECSuccess) {
                GEN_BREAK(rv);
            }
            pwitem.data = randomPassword;
            pwitem.len = RAND_PASS_LEN;
            pwitem.type = siBuffer;
        }

        keyOutFile = PR_Open(keyoutfile, PR_RDWR | PR_CREATE_FILE | PR_TRUNCATE, 00660);
        if (!keyOutFile) {
            SECU_PrintError(progName, "Unable to open \"%s\" for writing\n", keyoutfile);
            GEN_BREAK(255);
        }

        epki = PK11_ExportEncryptedPrivKeyInfo(NULL,
                algTag, &pwitem, privkey, 1000, pwdata);
        if (!epki) {
            rv = PORT_GetError();
            SECU_PrintError(progName, "Can't export private key info (%d)\n", rv);
            GEN_BREAK(rv);
        }

        arenaForEPKI = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
        assert(arenaForEPKI);

        if (keyEncPwd) {
            /* NULL dest to let it allocate memory for us */
            encryptedKeyDER = SEC_ASN1EncodeItem(arenaForEPKI, NULL, epki,
                SECKEY_EncryptedPrivateKeyInfoTemplate);
            if (!encryptedKeyDER) {
                rv = PR_GetError();
            	SECU_PrintError(progName, "ASN1 Encode failed (%s)\n",
                    SECU_Strerror(rv));
                GEN_BREAK(rv);
            }

        } else {
            /* Make a decrypted key the one to write out. */

            arenaForPKI = PORT_NewArena(2048);
            if (!arenaForPKI) {
                GEN_BREAK(PR_OUT_OF_MEMORY_ERROR);
            }

            clearKeyDER.data = PORT_ArenaAlloc(arenaForPKI, epki->encryptedData.len);
            clearKeyDER.len = epki->encryptedData.len;
            clearKeyDER.type = siBuffer;

            rv = DecryptKey(epki, algTag, &pwitem, pwdata, &clearKeyDER);
            if (rv != SECSuccess) {
                GEN_BREAK(rv);
            }
        }

        if (ascii) {
            /* we could be exporting a clear or encrypted key */
            SECItem *src  = keyEncPwd ? encryptedKeyDER : &clearKeyDER;
            char *header  = keyEncPwd ? ENCRYPTED_KEY_HEADER : KEY_HEADER;
            char *trailer = keyEncPwd ? ENCRYPTED_KEY_TRAILER : KEY_TRAILER;
            char *b64 = NULL;
            do {

                b64 = BTOA_ConvertItemToAscii(src);
                if (!b64) {
                    rv = 255;
                	GEN_BREAK(rv);
                }

                total = PL_strlen(b64);

                PR_fprintf(keyOutFile, "%s\n", header);

                numBytes = PR_Write(keyOutFile, b64, total);

                if (numBytes != total) {
                    printf("Wrote  %d bytes, instead of %d\n", numBytes, total);
                    break;
                }

                PR_fprintf(keyOutFile, "\n%s\n", trailer);

            } while (0);

            if (b64) {
            	PORT_Free(b64);
            }

        } else {
            if (keyEncPwd) {
            	/* Write out the encrypted key */
                numBytes = PR_Write(keyOutFile, encryptedKeyDER, encryptedKeyDER->len);
            } else {
            	/* Write out the unencrypted key */
                numBytes = PR_Write(keyOutFile, &clearKeyDER, clearKeyDER.len);
                if (numBytes != clearKeyDER.len) {
                    printf("Wrote  %d bytes, instead of %d\n", numBytes, clearKeyDER.len);
                }
            }
        }

        if (rv == SECSuccess)
            printf("Wrote %d bytes of encoded data to %s \n", numBytes, keyoutfile);

    } while (0);

    if (keyOutFile) {
        PR_Close(keyOutFile);
    }

    if (arenaForEPKI) {
        PORT_FreeArena(arenaForEPKI, PR_FALSE);
    }

    if (arenaForPKI) {
        PORT_FreeArena(arenaForPKI, PR_FALSE);
    }

    if (!keyEncPwd) {
        /* paranoia, though stack-based object we clear it anyway */
    	memset(randomPassword, 0, RAND_PASS_LEN);
    } else {
    	if (pwitem.data) {
    		memset(pwitem.data, 0, pwitem.len);
    		PORT_Free(pwitem.data);
    	}
        memset(&pwitem, 0, sizeof(SECItem));
    }

    return rv;
}

/* Generate a certificate signing request
 * or a self_signed certificate.
 */
static int keyutil_main(
        CERTCertDBHandle *certHandle,
        const char       *noisefile,
        const char       *access_pwd_file,
        const char       *keyEncPwd,
        const char       *cert_to_renew,
        const char       *input_key_file,
        PRBool           cacert,
        const char       *subjectstr,
        int              keysize,
        int              warpmonths,
        int              validityMonths,
        PRBool           ascii,
        const char       *certreqfile,
        const char       *certfile,
        const char       *keyoutfile)
{
    CERTCertificate *cert       = NULL;
    PRFileDesc *outFile         = NULL;
    PRFileDesc *keyOutFile      = NULL;
    CERTName   *subject         = NULL;
    SECKEYPrivateKey *privkey   = NULL;
    SECKEYPublicKey *pubkey     = NULL;
    PK11SlotInfo *slot          = NULL;
    secuPWData  pwdata          = { PW_NONE, 0 };
    KeyType     keytype         = rsaKey;
    SECOidTag   hashAlgTag      = SEC_OID_UNKNOWN;
    PRBool      doCert          = certfile != NULL;
    int         rv;

    if (access_pwd_file) {
        pwdata.source = PW_FROMFILE;
        pwdata.data = (char *)access_pwd_file;
        rv = nss_Init_Tokens(&pwdata);
        if (SECSuccess != rv) {
        	goto shutdown;
        }
    }

    if (cert_to_renew && input_key_file) {
        /*
         * This certificate request is for a renewal,
         * using existing keys.
         */
    	CK_SLOT_ID slotID = cacert ? 0 : 1;
    	char slotname[32];
    	char nickname[256];
    	CERTCertificate *keycert = NULL;
    	const char *n = cert_to_renew;

    	/* Remove the path part */
        n = strrchr(cert_to_renew, '/');
        if (!n)
            n = cert_to_renew;
        else
            n++;

        snprintf(slotname, 32, "PEM Token #%ld", slotID);
        snprintf(nickname, 256, "PEM Token #%ld:%s", slotID, n);
        slot = PK11_FindSlotByName(slotname);
        if (!slot) {
            printf("%s: Can't find slot for %s\n", progName, slotname);
            rv = 255;
            goto shutdown;
        }

        rv = loadCertAndKey(slot, cacert,
                            cert_to_renew, nickname, input_key_file,
                            &pwdata);

        if (rv != SECSuccess) {
	        SECU_PrintError(progName, "Can't load the key or cert, bailing out\n");
	    goto shutdown;
        }

        rv = extractRSAKeysAndSubject(nickname,
                slot, &pwdata, &privkey, &pubkey, &subject);
        if (rv != SECSuccess) {
            if (keycert) {
            	CERT_DestroyCertificate(keycert);
            }
          goto shutdown;
        }

        assert(privkey);
        assert(pubkey);
        assert(subject);

        printf("Read keys and subject from the cert to renew\n");

    } else {
        /*
         * This is a certificate signing request for a new cert,
         * will generate a key pair
         */

        if (!subjectstr) {
            SECU_PrintError(progName, "subject string was NULL\n");
            rv = 255;
            goto shutdown;
        }
        slot = PK11_GetInternalKeySlot(); /* PK11_GetInternalSlot() ? */

        privkey = GenerateRSAPrivateKey(keytype, slot,
            keysize, 65537L, (char *)noisefile, &pubkey, &pwdata);

        if (!privkey) {
            SECU_PrintError(progName,
                "Keypair generation failed: \"%d\"\n", PORT_GetError());
            rv = 255;
            goto shutdown;
        }

        subject = CERT_AsciiToName((char *)subjectstr);
        if (!subject) {
            SECU_PrintError(progName,
                "Improperly formatted name: \"%s\"\n", subjectstr);
            rv = 255;
            goto shutdown;
        }
        printf("Made a key\n");
    }

    outFile = PR_Open(certreqfile, PR_RDWR | PR_CREATE_FILE | PR_TRUNCATE, 00660);
    if (!outFile) {
        SECU_PrintError(progName,
               "%s -o: unable to open \"%s\" for writing (%ld, %ld)\n",
               certreqfile, PR_GetError(), PR_GetOSError());
        return 255;
    }
    printf("Opened %s for writing\n", certreqfile);

    /*
     *  Certificate request
     */

    /* Extensions not supported yet */
    keyutil_extns[ext_keyUsage] = PR_FALSE;
    keyutil_extns[ext_basicConstraint] = PR_FALSE;
    keyutil_extns[ext_authorityKeyID] = PR_FALSE;
    keyutil_extns[ext_subjectKeyID] = PR_FALSE;
    keyutil_extns[ext_CRLDistPts] = PR_FALSE;
    keyutil_extns[ext_NSCertType] = PR_FALSE;
    keyutil_extns[ext_extKeyUsage] = PR_FALSE;
    keyutil_extns[ext_authInfoAcc] = PR_FALSE;
    keyutil_extns[ext_subjInfoAcc] = PR_FALSE;
    keyutil_extns[ext_certPolicies] = PR_FALSE;
    keyutil_extns[ext_policyMappings] = PR_FALSE;
    keyutil_extns[ext_policyConstr] = PR_FALSE;
    keyutil_extns[ext_inhibitAnyPolicy] = PR_FALSE;

    hashAlgTag = SEC_OID_MD5;

    /*  Make a cert request */
    rv = CertReq(privkey, pubkey, rsaKey, hashAlgTag, subject,
                 NULL,         /* PhoneNumber */
                 ascii,        /* ASCIIForIO */
                 NULL,         /* ExtendedEmailAddrs */
                 NULL,         /* ExtendedDNSNames */
                 keyutil_extns, /* keyutil_extns */
                 outFile);

    PR_Close(outFile);
    if (rv) {
        SECU_PrintError(progName ? progName : "keyutil",
                "CertReq failed: \"%s\"\n", SECU_Strerror(rv));
        rv = 255;
        goto shutdown;
    }

    if (doCert) {

        /* If making a cert, we already have a cert request file.
         * without any extensions, load it with any command line extensions
         * and output the cert to other file. Delete the request file.
         */
        PRFileDesc *inFile = NULL;
        unsigned int serialNumber;

        /*  Make a default serial number from the current time.  */
        PRTime now = PR_Now();
        LL_USHR(now, now, 19);
        LL_L2UI(serialNumber, now);

        privkey->wincx = &pwdata;

        inFile  = PR_Open(certreqfile, PR_RDONLY, 0);
        assert(inFile);
        if (!inFile) {
            SECU_PrintError(progName, "Failed to open file \"%s\" (%ld, %ld) for reading.\n",
                  certreqfile, PR_GetError(), PR_GetOSError());
            rv = SECFailure;
            goto shutdown;
        }

        outFile = PR_Open(certfile, PR_RDWR | PR_CREATE_FILE | PR_TRUNCATE, 00660);
        if (!outFile) {
            SECU_PrintError(progName, "Failed to open file \"%s\" (%ld, %ld).\n",
                       certfile, PR_GetError(), PR_GetOSError());
            rv = SECFailure;
            goto    shutdown;
        }

        /*  Create a certificate (-C or -S).  */

        /* issuerName == subject */
        rv = CreateCert(certHandle,
            "tempnickname", inFile, outFile,
            privkey, &pwdata, hashAlgTag,
            serialNumber, warpmonths, validityMonths,
            NULL, NULL, ascii, PR_TRUE, keyutil_extns,
            &cert);
         /*
          ExtendedEmailAddrs,ExtendedDNSNames,
          ASCIIForIO,SelfSign,certutil_extns, thecert
         */
         if (rv) {
             SECU_PrintError(progName, "Failed to create certificate \"%s\" (%ld).\n",
                   outFile, PR_GetError());
             rv = SECFailure;
             goto shutdown;
         }
         printf("Created a certificate\n");

         /*  Sanity check: Check cert validity against current time. */

         /* for fips - must log in to get private key */
        if (slot && PK11_NeedLogin(slot)) {
            SECStatus newrv = PK11_Authenticate(slot, PR_TRUE, &pwdata);
            if (newrv != SECSuccess) {
                SECU_PrintError(progName, "could not authenticate to token %s.",
                            PK11_GetTokenName(slot));
                goto shutdown;
            }
            printf("Authenticated to token\n");
        }
    } else {
    	printf("Wrote the CSR to %s\n", certreqfile);
    }

    /* If the caller wants the private key extract it and save it to a file. */
    if (keyoutfile) {
        /* Two candidate tags to use: SEC_OID_DES_EDE3_CBC and
         * SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC
         */
        rv = KeyOut(keyoutfile, keyEncPwd,
                privkey, pubkey, SEC_OID_DES_EDE3_CBC,
                &pwdata, ascii);
        if (rv != SECSuccess) {
            SECU_PrintError(progName, "Failed to write the key");
        } else {
            printf("Wrote the key to:\n%s\n", keyoutfile);
        }
    }

shutdown:
    if (cert) {
        CERT_DestroyCertificate(cert);
    }
    if (keyOutFile) {
        PR_Close(keyOutFile);
    }
    if (slot) {
        PK11_FreeSlot(slot);
    }
    if (privkey) {
        SECKEY_DestroyPrivateKey(privkey);
    }
    if (pubkey) {
        SECKEY_DestroyPublicKey(pubkey);
    }
    if (mod) {
        rv = SECMOD_UnloadUserModule(mod);
        mod = NULL;
    }

    return rv == SECSuccess ? 0 : 255;
}

/* $Id: keyutil.c,v 1.15 2009/03/15 18:22:02 emaldonado Exp $ */

/* Key generation, encryption, and certificate utility code, based on
 * code from NSS's security utilities and the certutil application.
 * Elio Maldonado <emaldona@redhat.com>
 */


int main(int argc, char **argv)
{
    int optc, rv = 0;
    char *cmdstr = NULL;
    char *noisefile = NULL;
    int  keysize = 1024;
    int  warpmonths = 0;
    int  validity_months = 24;
    char *keyfile = NULL;
    char *outfile = NULL;
    char *cert_to_renew = NULL;
    char *subject = NULL;
    char *access_pwd_file = NULL;
    char *keyEncPwd = NULL;
    char *digestAlgorithm = "md5";
    char *keyoutfile = 0;
    PRBool ascii = PR_FALSE;
    PRBool cacert = PR_FALSE;
    CERTCertDBHandle *certHandle = 0;
    SECStatus status = 0;
    CommandType cmd = cmd_CertReq;
    PRBool initialized = PR_FALSE;

    while ((optc = getopt_long(argc, argv, "atc:rs:g:v:e:f:d:z:i:p:o:k:h", options, NULL)) != -1) {
        switch (optc) {
        case 'a':
            ascii = PR_TRUE;
            break;
        case 't':
            cacert = PR_TRUE;
            break;
        case 'c':
            cmdstr = strdup(optarg);
            printf("cmdstr: %s\n", cmdstr);
            if (strcmp(cmdstr, "genreq") == 0) {
                cmd = cmd_CertReq;
                printf("\ncmd_CertReq\n");
            } else if (strcmp(cmdstr, "makecert") == 0) {
                cmd = cmd_CreateNewCert;
                printf("\ncmd_CreateNewCert\n");
            } else {
                printf("\nInvalid argument: %s\n", cmdstr);
                exit(2);
            }
            printf("command:  %s\n", cmdstr);
            break;
        case 'r':
            cert_to_renew = strdup(optarg);
            break;
        case 's':
            subject = strdup(optarg);
            printf("subject = %s\n", subject);
            break;
        case 'g':
            keysize = atoi(optarg);
            printf("keysize = %d bits\n", keysize);
            break;
        case 'v':
            validity_months = atoi(optarg);
            printf("valid for %d months\n", validity_months);
            break;
        case 'e':
            keyEncPwd = strdup(optarg);
            printf("key encryption password = ****\n");
            break;
        case 'f':
            access_pwd_file = strdup(optarg);
            printf("module access password from %s\n", access_pwd_file);
            break;
        case 'd':
            digestAlgorithm = strdup(optarg);
            printf("message digest %s\n", digestAlgorithm);
            break;
        case 'z':
            noisefile = strdup(optarg);
            printf("random seed from %s\n", noisefile);
            break;
        case 'i':
            keyfile = strdup(optarg);
            printf("will process a key from %s\n", keyfile);
            break;
        case 'o':
            /* could be req or cert */
            outfile = strdup(optarg);
            printf("output will be written to %s\n", outfile);
            break;
        case 'k':
            /* private key out in plaintext - side effect of req and cert */
            keyoutfile = strdup(optarg);
            printf("output key written to %s\n", keyoutfile);
            break;
        case 'h':
            Usage(progName);
            break;
        default:
            printf("Bad arguments\n");
            Usage(progName);
            break;
        }
    }

    /*  Initialize NSPR and NSS.  */
    PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);

    status = NSS_NoDB_Init(NULL);
    if (status  != SECSuccess ) {
        printf("NSS initialization failed\n");
        return EXIT_FAILURE;
    }
    if (cert_to_renew) {
        char *configstring = NULL;
        /* Load our PKCS#11 module */
        configstring = (char *)malloc(4096);
        PR_snprintf(configstring, 4096,
                    "library=%s name=PEM parameters=\"\"", pem_library);
        mod = SECMOD_LoadUserModule(configstring, NULL, PR_FALSE);
        if (!mod || !mod->loaded) {
            printf("%s: Failed to load %s\n", progName, pem_library);
        }
        free(configstring);
        if (!mod) {
            NSS_Shutdown();
            PR_Cleanup();
            return EXIT_FAILURE;
    	}
        if (PK11_IsFIPS() && !access_pwd_file) {
    	    printf("Default module in FIPS mode requires password\n");
            return EXIT_FAILURE;
        }
    }
    initialized = PR_TRUE;

    certHandle = CERT_GetDefaultCertDB();
    assert(certHandle);

    switch (cmd) {
    case cmd_CertReq:
        /* certfile NULL signals only the request is needed */
        rv = keyutil_main(certHandle,
                noisefile, access_pwd_file, keyEncPwd,
                cert_to_renew, keyfile, cacert,
                subject, keysize, warpmonths, validity_months,
                ascii, outfile, NULL, keyoutfile);
        break;
    case cmd_CreateNewCert:
        rv = keyutil_main(certHandle,
                noisefile, access_pwd_file, keyEncPwd,
                NULL, NULL, cacert, /* ignored */
                subject, keysize, warpmonths, validity_months,
                ascii, "tmprequest", outfile, keyoutfile);
        break;
    default:
        printf("\nEntered an inconsistent state, bailing out\n");
        rv = -1;
        break;
    }

    if ((initialized == PR_TRUE) && NSS_Shutdown() != SECSuccess) {
        exit(1);
    }
    PR_Cleanup();

    return rv;
}
