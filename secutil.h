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
#ifndef _SEC_UTIL_H_
#define _SEC_UTIL_H_

#include <seccomon.h>
#include <secitem.h>
#include <prerror.h>
#include <base64.h>
#include <key.h>
#include <secpkcs7.h>
#include <secasn1.h>
#include <secder.h>
#include <stdio.h>

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

/* From libsec/pcertdb.c --- it's not declared in sec.h */
extern SECStatus SEC_AddPermCertificate(CERTCertDBHandle *handle,
        SECItem *derCert, char *nickname, CERTCertTrust *trust);


#ifdef SECUTIL_NEW
typedef int (*SECU_PPFunc)(PRFileDesc *out, SECItem *item, 
                           char *msg, int level);
#else
typedef int (*SECU_PPFunc)(FILE *out, SECItem *item, char *msg, int level);
#endif

typedef struct {
    enum {
    PW_NONE = 0,
    PW_FROMFILE = 1,
    PW_PLAINTEXT = 2,
    PW_EXTERNAL = 3
    } source;
    char *data;
} secuPWData;

extern char *SECU_FilePasswd(PK11SlotInfo *slot, PRBool retry, void *arg);
extern char *SECU_NoPassword(PK11SlotInfo *slot, PRBool retry, void *arg);
extern char *SECU_GetModulePassword(PK11SlotInfo *slot, PRBool retry, void *arg);

/* print out an error message */
extern void SECU_PrintError(char *progName, char *msg, ...);

/* print out a system error message */
extern void SECU_PrintSystemError(char *progName, char *msg, ...);

/* Return informative error string */
extern const char * SECU_Strerror(PRErrorCode errNum);

/* Read the contents of a file into a SECItem */
extern SECStatus SECU_FileToItem(SECItem *dst, PRFileDesc *src);
extern SECStatus SECU_TextFileToItem(SECItem *dst, PRFileDesc *src);

/* Read in a DER from a file, may be ascii  */
extern SECStatus 
SECU_ReadDERFromFile(SECItem *der, PRFileDesc *inFile, PRBool ascii);

/* Indent based on "level" */
extern void SECU_Indent(FILE *out, int level);

/* Print ObjectIdentifier symbolically */
extern SECOidTag SECU_PrintObjectID(FILE *out, SECItem *oid, char *m, int level);

/* Print SECItem as hex */
extern void SECU_PrintAsHex(FILE *out, SECItem *i, const char *m, int level);

typedef enum  {
    noKeyFound = 1,
    noSignatureMatch = 2,
    failToEncode = 3,
    failToSign = 4,
    noMem = 5
} SignAndEncodeFuncExitStat;

/* call back function used in encoding of an extension. Called from
 * SECU_EncodeAndAddExtensionValue */
typedef SECStatus (* EXTEN_EXT_VALUE_ENCODER) (PRArenaPool *extHandleArena,
                                               void *value, SECItem *encodedValue);

/* Encodes and adds extensions to the CRL or CRL entries. */
SECStatus 
SECU_EncodeAndAddExtensionValue(PRArenaPool *arena, void *extHandle, 
                                void *value, PRBool criticality, int extenType, 
                                EXTEN_EXT_VALUE_ENCODER EncodeValueFn);

/* Caller ensures that dst is at least item->len*2+1 bytes long */
void
SECU_SECItemToHex(const SECItem * item, char * dst);

/* Requires 0x prefix. Case-insensitive. Will do in-place replacement if
 * successful */
SECStatus
SECU_SECItemHexStringToBinary(SECItem* srcdest);

/*
 *
 *  Error messaging
 *
 */

/* Return informative error string */
char *SECU_ErrorString(int16 err);


#include <secerr.h>
#include <sslerr.h>

#endif /* _SEC_UTIL_H_ */
