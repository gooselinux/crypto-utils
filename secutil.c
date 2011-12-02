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
** secutil.c - various functions used by security stuff
** 
** This code comes from the NSS internal library used by the
** the NSS security tools.
**
*/

#include <prtypes.h>
#include <prtime.h>
#include <prlong.h>
#include <prerror.h>
#include <prprf.h>
#include <plgetopt.h>
#include <prenv.h>
#include <prnetdb.h>

#include <cryptohi.h>
#include <secpkcs7.h>
#include <secpkcs5.h>
#include <stdarg.h>

#include <sys/stat.h>
#include <errno.h>

#include <unistd.h>

/* for SEC_TraverseNames */
#include <cert.h>
#include <certt.h>
#include <certdb.h>

#include <secmod.h>
#include <pk11func.h>
#include <secoid.h>

#include "secutil.h"

#if(0)
static char consoleName[] =  {
    "/dev/tty"
};
#endif

char *
SECU_GetString(int16 error_number)
{

    static char errString[80];
    sprintf(errString, "Unknown error string (%d)", error_number);
    return errString;
}

void 
SECU_PrintErrMsg(FILE *out, int level, char *progName, char *msg, ...)
{
    va_list args;
    PRErrorCode err = PORT_GetError();
    const char * errString = SECU_Strerror(err);

    va_start(args, msg);

    SECU_Indent(out, level);
    fprintf(out, "%s: ", progName);
    vfprintf(out, msg, args);
    if (errString != NULL && PORT_Strlen(errString) > 0)
    fprintf(out, ": %s\n", errString);
    else
    fprintf(out, ": error %d\n", (int)err);

    va_end(args);
}

void SECU_PrintError(char *progName, char *msg, ...)
{
    SECU_PrintErrMsg(stderr, 0, progName, msg);
}

#define INDENT_MULT 4
void
SECU_Indent(FILE *out, int level)
{
    int i;

    for (i = 0; i < level; i++) {
    fprintf(out, "    ");
    }
}

static void secu_Newline(FILE *out)
{
    fprintf(out, "\n");
}

void
SECU_PrintAsHex(FILE *out, SECItem *data, const char *m, int level)
{
    unsigned i;
    int column;
    PRBool isString     = PR_TRUE;
    PRBool isWhiteSpace = PR_TRUE;
    PRBool printedHex   = PR_FALSE;
    unsigned int limit = 15;

    if ( m ) {
        SECU_Indent(out, level); fprintf(out, "%s:\n", m);
        level++;
    }
    
    SECU_Indent(out, level); column = level*INDENT_MULT;
    if (!data->len) {
        fprintf(out, "(empty)\n");
        return;
    }
    /* take a pass to see if it's all printable. */
    for (i = 0; i < data->len; i++) {
        unsigned char val = data->data[i];
        if (!val || !isprint(val)) {
            isString = PR_FALSE;
            break;
        }
        if (isWhiteSpace && !isspace(val)) {
            isWhiteSpace = PR_FALSE;
        }
    }

    /* Short values, such as bit strings (which are printed with this
    ** function) often look like strings, but we want to see the bits.
    ** so this test assures that short values will be printed in hex,
    ** perhaps in addition to being printed as strings.
    ** The threshold size (4 bytes) is arbitrary.
    */
    if (!isString || data->len <= 4) {
        for (i = 0; i < data->len; i++) {
            if (i != data->len - 1) {
                fprintf(out, "%02x:", data->data[i]);
                column += 3;
            } else {
                fprintf(out, "%02x", data->data[i]);
                column += 2;
                break;
            }
            if (column > 76 || (i % 16 == limit)) {
            	secu_Newline(out);
            	SECU_Indent(out, level); 
            	column = level*INDENT_MULT;
            	limit = i % 16;
            }
        }
        printedHex = PR_TRUE;
    }
	if (isString && !isWhiteSpace) {
	    if (printedHex != PR_FALSE) {
	        secu_Newline(out);
	        SECU_Indent(out, level); column = level*INDENT_MULT;
	    }
	    for (i = 0; i < data->len; i++) {
	        unsigned char val = data->data[i];
	
	        if (val) {
	        	fprintf(out,"%c",val);
	        	column++;
	        } else {
	        	column = 77;
	        }
	        if (column > 76) {
	        	secu_Newline(out);
	            SECU_Indent(out, level); column = level*INDENT_MULT;
	        }
	    }
	}
        
    if (column != level*INDENT_MULT) {
    	secu_Newline(out);
    }
}

/* This function does NOT expect a DER type and length. */
SECOidTag
SECU_PrintObjectID(FILE *out, SECItem *oid, char *m, int level)
{
    SECOidData *oiddata;
    char *oidString = NULL;
    
    oiddata = SECOID_FindOID(oid);
    if (oiddata != NULL) {
	    const char *name = oiddata->desc;
	    SECU_Indent(out, level);
	    if (m != NULL)
	        fprintf(out, "%s: ", m);
	    fprintf(out, "%s\n", name);
	    return oiddata->offset;
    } 
    oidString = CERT_GetOidString(oid);
    if (oidString) {
	    SECU_Indent(out, level);
	    if (m != NULL)
	        fprintf(out, "%s: ", m);
	    fprintf(out, "%s\n", oidString);
	    PR_smprintf_free(oidString);
	    return SEC_OID_UNKNOWN;
    }
    SECU_PrintAsHex(out, oid, m, level);
    return SEC_OID_UNKNOWN;
}

void
SECU_PrintSystemError(char *progName, char *msg, ...)
{
    va_list args;

    va_start(args, msg);
    fprintf(stderr, "%s: ", progName);
    vfprintf(stderr, msg, args);
    fprintf(stderr, ": %s\n", strerror(errno));
    va_end(args);
}

#if(0)
static void
secu_ClearPassword(char *p)
{
    if (p) {
	PORT_Memset(p, 0, PORT_Strlen(p));
	PORT_Free(p);
    }
}

char *
SECU_GetPasswordString(void *arg, char *prompt)
{
    char *p = NULL;
    FILE *input, *output;

    /* open terminal */
    input = fopen(consoleName, "r");
    if (input == NULL) {
	fprintf(stderr, "Error opening input terminal for read\n");
	return NULL;
    }

    output = fopen(consoleName, "w");
    if (output == NULL) {
	fprintf(stderr, "Error opening output terminal for write\n");
	return NULL;
    }

    p = SEC_GetPassword (input, output, prompt, SEC_BlindCheckPassword);
        
    fclose(input);
    fclose(output);

    return p;
}
#endif


/*
 *  p a s s w o r d _ h a r d c o d e 
 *
 *  A function to use the password passed in the -f(pwfile) argument
 *  of the command line.  
 *  After use once, null it out otherwise PKCS11 calls us forever.?
 *
 */
char *
SECU_FilePasswd(PK11SlotInfo *slot, PRBool retry, void *arg)
{
    char* phrases, *phrase;
    PRFileDesc *fd;
    PRInt32 nb;
    const char *pwFile = (const char *)arg;
    int i;
    const long maxPwdFileSize = 4096;
    char* tokenName = NULL;
    int tokenLen = 0;
    
    if (!pwFile) {
	    return 0;
    }

    if (retry) {
    	return 0;  /* no good retrying - the files contents will be the same */
    }

    phrases = PORT_ZAlloc(maxPwdFileSize);

    if (!phrases) {
        return 0; /* out of memory */
    }
 
    fd = PR_Open(pwFile, PR_RDONLY, 0);
    if (!fd) {
	    fprintf(stderr, "No password file \"%s\" exists.\n", pwFile);
        PORT_Free(phrases);
	    return NULL;
    }

    nb = PR_Read(fd, phrases, maxPwdFileSize);
  
    PR_Close(fd);

    if (nb == 0) {
        fprintf(stderr,"password file contains no data\n");
        PORT_Free(phrases);
        return NULL;
    }

    if (slot) {
        tokenName = PK11_GetTokenName(slot);
        if (tokenName) {
            tokenLen = PORT_Strlen(tokenName);
        }
    }
    i = 0;
    do {
        int startphrase = i;
        int phraseLen;

        /* handle the Windows EOL case */
        while (phrases[i] != '\r' && phrases[i] != '\n' && i < nb) i++;
        /* terminate passphrase */
        phrases[i++] = '\0';
        /* clean up any EOL before the start of the next passphrase */
        while ( (i<nb) && (phrases[i] == '\r' || phrases[i] == '\n')) {
            phrases[i++] = '\0';
        }
        /* now analyze the current passphrase */
        phrase = &phrases[startphrase];
        if (!tokenName)
            break;
        if (PORT_Strncmp(phrase, tokenName, tokenLen)) continue;
        phraseLen = PORT_Strlen(phrase);
        if (phraseLen < (tokenLen+1)) continue;
        if (phrase[tokenLen] != ':') continue;
        phrase = &phrase[tokenLen+1];
        break;

    } while (i<nb);

    phrase = PORT_Strdup((char*)phrase);
    PORT_Free(phrases);
    return phrase;
}

char *
SECU_GetModulePassword(PK11SlotInfo *slot, PRBool retry, void *arg) 
{
#if(0)
    char prompt[255];
#endif
    secuPWData *pwdata = (secuPWData *)arg;
    secuPWData pwnull = { PW_NONE, 0 };
    secuPWData pwxtrn = { PW_EXTERNAL, "external" };
    char *pw;

    if (pwdata == NULL)
        pwdata = &pwnull;

    if (PK11_ProtectedAuthenticationPath(slot)) {
        pwdata = &pwxtrn;
    }
    if (retry && pwdata->source != PW_NONE) {
        PR_fprintf(PR_STDERR, "Incorrect password/PIN entered.\n");
        return NULL;
    }

    switch (pwdata->source) {
#if(0)
    case PW_NONE:
        sprintf(prompt, "Enter Password or Pin for \"%s\":",
	            PK11_GetTokenName(slot));
        return SECU_GetPasswordString(NULL, prompt);
#endif

    case PW_FROMFILE:
	    /* Instead of opening and closing the file every time, get the pw
	     * once, then keep it in memory (duh).
	     */
	    pw = SECU_FilePasswd(slot, retry, pwdata->data);
	    pwdata->source = PW_PLAINTEXT;
	    pwdata->data = PL_strdup(pw);
	    /* it's already been dup'ed */
	    return pw;
#if(0)
    case PW_EXTERNAL:
        sprintf(prompt, 
	            "Press Enter, then enter PIN for \"%s\" on external device.\n",
                PK11_GetTokenName(slot));
        (void) SECU_GetPasswordString(NULL, prompt);
    	/* Fall Through */
#endif
   case PW_PLAINTEXT:
	    return PL_strdup(pwdata->data);
    default:
	    break;
    }

    PR_fprintf(PR_STDERR, "Password check failed:  No password found.\n");
    return NULL;
}

/*
 * Password callback so the user is not prompted to enter the password
 * after the server starts.
 */
char *SECU_NoPassword(PK11SlotInfo *slot, PRBool retry, void *arg)
{
    return NULL;
}

SECStatus
secu_StdinToItem(SECItem *dst)
{
    unsigned char buf[1000];
    PRInt32 numBytes;
    PRBool notDone = PR_TRUE;

    dst->len = 0;
    dst->data = NULL;

    while (notDone) {
    numBytes = PR_Read(PR_STDIN, buf, sizeof(buf));

    if (numBytes < 0) {
        return SECFailure;
    }

    if (numBytes == 0)
        break;

    if (dst->data) {
        unsigned char * p = dst->data;
        dst->data = (unsigned char*)PORT_Realloc(p, dst->len + numBytes);
        if (!dst->data) {
            PORT_Free(p);
        }
    } else {
        dst->data = (unsigned char*)PORT_Alloc(numBytes);
    }
    if (!dst->data) {
        return SECFailure;
    }
    PORT_Memcpy(dst->data + dst->len, buf, numBytes);
    dst->len += numBytes;
    }

    return SECSuccess;
}

SECStatus
SECU_FileToItem(SECItem *dst, PRFileDesc *src)
{
    PRFileInfo info;
    PRInt32 numBytes;
    PRStatus prStatus;

    if (src == PR_STDIN)
        return secu_StdinToItem(dst);

    prStatus = PR_GetOpenFileInfo(src, &info);

    if (prStatus != PR_SUCCESS) {
        PORT_SetError(SEC_ERROR_IO);
        return SECFailure;
    }

    /* XXX workaround for 3.1, not all utils zero dst before sending */
    dst->data = 0;
    if (!SECITEM_AllocItem(NULL, dst, info.size))
        goto loser;

    numBytes = PR_Read(src, dst->data, info.size);
    if (numBytes != info.size) {
        PORT_SetError(SEC_ERROR_IO);
        goto loser;
    }

    return SECSuccess;
loser:
    SECITEM_FreeItem(dst, PR_FALSE);
    dst->data = NULL;
    return SECFailure;
}

SECStatus
SECU_TextFileToItem(SECItem *dst, PRFileDesc *src)
{
    PRFileInfo info;
    PRInt32 numBytes;
    PRStatus prStatus;
    unsigned char *buf;

    if (src == PR_STDIN)
	return secu_StdinToItem(dst);

    prStatus = PR_GetOpenFileInfo(src, &info);

    if (prStatus != PR_SUCCESS) {
	PORT_SetError(SEC_ERROR_IO);
	return SECFailure;
    }

    buf = (unsigned char*)PORT_Alloc(info.size);
    if (!buf)
	return SECFailure;

    numBytes = PR_Read(src, buf, info.size);
    if (numBytes != info.size) {
	PORT_SetError(SEC_ERROR_IO);
	goto loser;
    }

    if (buf[numBytes-1] == '\n') numBytes--;
#ifdef _WINDOWS
    if (buf[numBytes-1] == '\r') numBytes--;
#endif

    /* XXX workaround for 3.1, not all utils zero dst before sending */
    dst->data = 0;
    if (!SECITEM_AllocItem(NULL, dst, numBytes))
	goto loser;

    memcpy(dst->data, buf, numBytes);

    PORT_Free(buf);
    return SECSuccess;
loser:
    PORT_Free(buf);
    return SECFailure;
}

SECStatus
SECU_ReadDERFromFile(SECItem *der, PRFileDesc *inFile, PRBool ascii)
{
    SECStatus rv;
    if (ascii) {
    /* First convert ascii to binary */
    SECItem filedata;
    char *asc, *body;

    /* Read in ascii data */
    rv = SECU_FileToItem(&filedata, inFile);
    asc = (char *)filedata.data;
    if (!asc) {
        fprintf(stderr, "unable to read data from input file\n");
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
            fprintf(stderr, "input has header but no trailer\n");
            PORT_Free(filedata.data);
            return SECFailure;
        }
    } else {
        body = asc;
    }
     
    /* Convert to binary */
    rv = ATOB_ConvertAsciiToItem(der, body);
    if (rv) {
        fprintf(stderr, "error converting ascii to binary (%d)\n",
            PORT_GetError());
        PORT_Free(filedata.data);
        return SECFailure;
    }

    PORT_Free(filedata.data);
    } else {
        /* Read in binary der */
        rv = SECU_FileToItem(der, inFile);
        if (rv) {
            fprintf(stderr, "error converting der (%d)\n", 
                PORT_GetError());
            return SECFailure;
        }
    }
    return SECSuccess;
}

/* Encodes and adds extensions to the CRL or CRL entries. */
SECStatus 
SECU_EncodeAndAddExtensionValue(PRArenaPool *arena, void *extHandle, 
                                void *value, PRBool criticality, int extenType, 
                                EXTEN_EXT_VALUE_ENCODER EncodeValueFn)
{
    SECItem encodedValue;
    SECStatus rv;

    encodedValue.data = NULL;
    encodedValue.len = 0;
    do {
        rv = (*EncodeValueFn)(arena, value, &encodedValue);
        if (rv != SECSuccess)
            break;

        rv = CERT_AddExtension(extHandle, extenType, &encodedValue,
                               criticality, PR_TRUE);
        if (rv != SECSuccess)
            break;
        
    } while (0);

    return (rv);
}

/* Caller ensures that dst is at least item->len*2+1 bytes long */
void
SECU_SECItemToHex(const SECItem * item, char * dst)
{
    if (dst && item && item->data) {
        unsigned char * src = item->data;
        unsigned int    len = item->len;
        for (; len > 0; --len, dst += 2) {
            sprintf(dst, "%02x", *src++);
        }
        *dst = '\0';
    }
}

static unsigned char nibble(char c) {
    c = PORT_Tolower(c);
    return ( c >= '0' && c <= '9') ? c - '0' :
           ( c >= 'a' && c <= 'f') ? c - 'a' +10 : -1;
}

SECStatus
SECU_SECItemHexStringToBinary(SECItem* srcdest)
{
    int i;

    if (!srcdest) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }
    if (srcdest->len < 4 || (srcdest->len % 2) ) {
        /* too short to convert, or even number of characters */
        PORT_SetError(SEC_ERROR_BAD_DATA);
        return SECFailure;
    }
    if (PORT_Strncasecmp((const char*)srcdest->data, "0x", 2)) {
        /* wrong prefix */
        PORT_SetError(SEC_ERROR_BAD_DATA);
        return SECFailure;
    }

    /* 1st pass to check for hex characters */
    for (i=2; i<srcdest->len; i++) {
        char c = PORT_Tolower(srcdest->data[i]);
        if (! ( ( c >= '0' && c <= '9') ||
                ( c >= 'a' && c <= 'f')
              ) ) {
            PORT_SetError(SEC_ERROR_BAD_DATA);
            return SECFailure;
        }
    }

    /* 2nd pass to convert */
    for (i=2; i<srcdest->len; i+=2) {
        srcdest->data[(i-2)/2] = (nibble(srcdest->data[i]) << 4) +
                                 nibble(srcdest->data[i+1]);
    }

    /* adjust length */
    srcdest->len -= 2;
    srcdest->len /= 2;
    return SECSuccess;
}
