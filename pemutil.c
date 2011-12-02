/*
   Copyright 2008 Red Hat, Inc.

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

/* Certificate processing utilities, based on code from Mozilla
 * Network Security Services internal secutils static library.
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
 * The exported function here is PEMUTIL_PEM_read_X509. A function like
 * this belongs in nss_compat_ossl. Elio Maldonado <emaldona@redhat.com> 
 */

#include <cert.h>
#include <certt.h>
#include <nspr.h>
#include <seccomon.h>
#include <base64.h>
#include <assert.h>

#define TIME_BUF_SIZE 100

/* decode a SECItem containing either a SEC_ASN1_GENERALIZED_TIME 
   or a SEC_ASN1_UTC_TIME */
extern SECStatus DER_DecodeTimeChoice(PRTime* output, const SECItem* input);


/* Loads the contents of a file into a SECItem.
 * Code is from the NSS security utilities.
 */
static SECStatus FileToItem(SECItem *dst, PRFileDesc *src)
{
    PRFileInfo info;
    PRInt32 numBytes;
    PRStatus prStatus;

    prStatus = PR_GetOpenFileInfo(src, &info);

    if (prStatus != PR_SUCCESS) {
        return SECFailure;
    }

    /* XXX workaround for 3.1, not all utils zero dst before sending */
    dst->data = 0;
    if (!SECITEM_AllocItem(NULL, dst, info.size))
        goto loser;

    numBytes = PR_Read(src, dst->data, info.size);
    if (numBytes != info.size)
        goto loser;

    return SECSuccess;
loser:
    SECITEM_FreeItem(dst, PR_FALSE);
    dst->data = NULL;
    return SECFailure;
}

/* Load a DER encoding into a SECItem.
 * Code is from the NSS security utilities.
 */
static SECStatus ReadDERFromFile(SECItem *der, PRFileDesc *inFile, PRBool ascii)
{
    SECStatus rv;
    if (ascii) {
        /* First convert ascii to binary */
        SECItem filedata;
        char *asc, *body;
    
        /* Read in ascii data */
        rv = FileToItem(&filedata, inFile);
        asc = (char *)filedata.data;
        if (!asc) {
            return SECFailure;
        }
    
        /* check for headers and trailers and remove them */
        if ((body = strstr(asc, "-----BEGIN")) != NULL) {
            char *trailer = NULL;
            asc = body;
            body = PORT_Strchr(body, '\n');
            if (!body)
                body = PORT_Strchr(asc, '\r'); /* maybe this is a MAC file */
            if (body)
                trailer = strstr(++body, "-----END");
            if (trailer != NULL) {
                *trailer = '\0';
            } else {
                /*printf("input has header but no trailer\n");*/
                PORT_Free(filedata.data);
                return SECFailure;
           }
        } else {
            body = asc;
        }
         
        /* Convert to binary */
        rv = ATOB_ConvertAsciiToItem(der, body);
        if (rv) {
            /* printf("ATOB_ConvertAsciiToItem failed\n");*/
            PORT_Free(filedata.data);
            return SECFailure;
        }
    
        PORT_Free(filedata.data);
    } else {
        /* Read in binary der */
        rv = FileToItem(der, inFile);
        if (rv) {
            return SECFailure;
        }
    }
    return SECSuccess;
}


/* Return a certificate structure from a pem-encoded cert in a file; 
 * or NULL on failure. Semantics similar to an OpenSSL
 * PEM_read_X509(fp, NULL, NULL, NULL); call
 */
CERTCertificate *
PEMUTIL_PEM_read_X509(const char *filename)
{
    CERTCertificate *cert = NULL;
    PRFileDesc *fd = NULL;
    SECItem derCert;

    fd = PR_Open(filename, PR_RDONLY, 0);
    if (!fd) return NULL;

    /* Read in a DER from a file, it is ascii */
    if (SECSuccess != ReadDERFromFile(&derCert, fd, PR_TRUE))
        goto cleanup;
   
    /* create a temporary cert in the database */
    cert = CERT_NewTempCertificate(CERT_GetDefaultCertDB(), 
            &derCert, NULL, PR_FALSE, PR_FALSE);
               /* noNickname, notPerm, noCopy */
 cleanup:
    if (fd) PR_Close(fd);

    return cert;
}
