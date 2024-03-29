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
** certext.c
**
** part of certutil for managing certificates extensions
**
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "secutil.h"

#include <unistd.h>

#include <cert.h>
#include <prprf.h>
#include <certt.h>

#include "keyutil.h"

#define GEN_BREAK(e) rv=e; break;

/* CERT_EncodeSubjectKeyID is a private function decleared in <xconst.h> */

/* Begin From NSS's xconst.c */
static const SEC_ASN1Template CERTSubjectKeyIDTemplate[] = {
    { SEC_ASN1_OCTET_STRING }
};

SECStatus 
CERT_EncodeSubjectKeyID(PRArenaPool *arena, const SECItem* srcString,
                        SECItem *encodedValue)
{
    SECStatus rv = SECSuccess;

    if (!srcString) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }
    if (SEC_ASN1EncodeItem (arena, encodedValue, srcString,
                CERTSubjectKeyIDTemplate) == NULL) {
        rv = SECFailure;
    }
    
    return(rv);
}
/* End From xconst.c */


/* From oidstring.c */
/* if to->data is not NULL, and to->len is large enough to hold the result,
 * then the resultant OID will be copyed into to->data, and to->len will be
 * changed to show the actual OID length.
 * Otherwise, memory for the OID will be allocated (from the caller's 
 * PLArenaPool, if pool is non-NULL) and to->data will receive the address
 * of the allocated data, and to->len will receive the OID length.
 * The original value of to->data is not freed when a new buffer is allocated.
 * 
 * The input string may begin with "OID." and this still be ignored.
 * The length of the input string is given in len.  If len == 0, then 
 * len will be computed as strlen(from), meaning it must be NUL terminated.
 * It is an error if from == NULL, or if *from == '\0'.
 */

SECStatus
SEC_StringToOID(PLArenaPool *pool, SECItem *to, const char *from, PRUint32 len)
{
    /*PRUint32 result_len = 0;*/
    PRUint32 decimal_numbers = 0;
    PRUint32 result_bytes = 0;
    SECStatus rv;
    PRUint8 result[1024];

    static const PRUint32 max_decimal = (0xffffffff / 10);
    static const char OIDstring[] = {"OID."};

    if (!from || !to) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
    return SECFailure;
    }
    if (!len) {
        len = PL_strlen(from);
    }
    if (len >= 4 && !PL_strncasecmp(from, OIDstring, 4)) {
        from += 4; /* skip leading "OID." if present */
        len  -= 4;
    }
    if (!len) {
bad_data:
        PORT_SetError(SEC_ERROR_BAD_DATA);
        return SECFailure;
    }
    do {
        PRUint32 decimal = 0;
            while (len > 0 && isdigit(*from)) {
            PRUint32 addend = (*from++ - '0');
            --len;
            if (decimal > max_decimal)  /* overflow */
            goto bad_data;
            decimal = (decimal * 10) + addend;
            if (decimal < addend)   /* overflow */
            goto bad_data;
        }
        if (len != 0 && *from != '.') {
            goto bad_data;
        }
        if (decimal_numbers == 0) {
            if (decimal > 2)
                goto bad_data;
            result[0] = decimal * 40;
            result_bytes = 1;
        } else if (decimal_numbers == 1) {
            if (decimal > 40)
                goto bad_data;
            result[0] += decimal;
        } else {
            /* encode the decimal number,  */
            PRUint8 * rp;
            PRUint32 num_bytes = 0;
            PRUint32 tmp = decimal;
            while (tmp) {
                num_bytes++;
                tmp >>= 7;
            }
            if (!num_bytes )
                ++num_bytes;  /* use one byte for a zero value */
            if (num_bytes + result_bytes > sizeof result)
                goto bad_data;
            tmp = num_bytes;
            rp = result + result_bytes - 1;
            rp[tmp] = (PRUint8)(decimal & 0x7f);
            decimal >>= 7;
            while (--tmp > 0) {
                rp[tmp] = (PRUint8)(decimal | 0x80);
                decimal >>= 7;
            }
            result_bytes += num_bytes;
        }
        ++decimal_numbers;
        if (len > 0) { /* skip trailing '.' */
            ++from;
            --len;
        }
    } while (len > 0);
    /* now result contains result_bytes of data */
    if (to->data && to->len >= result_bytes) {
        PORT_Memcpy(to->data, result, to->len = result_bytes);
        rv = SECSuccess;
    } else {
        SECItem result_item = {siBuffer, NULL, 0 };
        result_item.data = result;
        result_item.len  = result_bytes;
        rv = SECITEM_CopyItem(pool, to, &result_item);
    }
    return rv;
}

static char *
Gets_s(char *buff, size_t size) {
    char *str;
    
    if (buff == NULL || size < 1) {
        PORT_Assert(0);
        return NULL;
    }
    if ((str = fgets(buff, size, stdin)) != NULL) {
        int len = PORT_Strlen(str);
        /*
         * fgets() automatically converts native text file
         * line endings to '\n'.  As defensive programming
         * (just in case fgets has a bug or we put stdin in
         * binary mode by mistake), we handle three native 
         * text file line endings here:
         *   '\n'      Unix (including Linux and Mac OS X)
         *   '\r''\n'  DOS/Windows & OS/2
         *   '\r'      Mac OS Classic
         * len can not be less then 1, since in case with
         * empty string it has at least '\n' in the buffer
         */
        if (buff[len - 1] == '\n' || buff[len - 1] == '\r') {
            buff[len - 1] = '\0';
            if (len > 1 && buff[len - 2] == '\r')
                buff[len - 2] = '\0';
        }
    } else {
        buff[0] = '\0';
    }
    return str;
}


static SECStatus
PrintChoicesAndGetAnswer(char* str, char* rBuff, int rSize)
{
    fprintf(stdout, str);
    fprintf(stdout, " > ");
    fflush (stdout);
    if (Gets_s(rBuff, rSize) == NULL) {
        PORT_SetError(SEC_ERROR_INPUT_LEN);
        return SECFailure;
    }
    return SECSuccess;
}

static CERTGeneralName *
GetGeneralName (PRArenaPool *arena)
{
    CERTGeneralName *namesList = NULL;
    CERTGeneralName *current;
    CERTGeneralName *tail = NULL;
    SECStatus rv = SECSuccess;
    int intValue;
    char buffer[512];
    void *mark;

    PORT_Assert (arena);
    mark = PORT_ArenaMark (arena);
    do {
        if (PrintChoicesAndGetAnswer(
        "\nSelect one of the following general name type: \n"
        "\t2 - rfc822Name\n"
        "\t3 - dnsName\n"
        "\t5 - directoryName\n"
        "\t7 - uniformResourceidentifier\n"
        "\t8 - ipAddress\n"
        "\t9 - registerID\n"
        "\tAny other number to finish\n"
        "\t\tChoice:", buffer, sizeof(buffer)) == SECFailure) {
            GEN_BREAK (SECFailure);
        }
        intValue = PORT_Atoi (buffer);
        /*
         * Should use ZAlloc instead of Alloc to avoid problem with garbage
         * initialized pointers in CERT_CopyName
         */
        switch (intValue) {
        case certRFC822Name:
        case certDNSName:
        case certDirectoryName:
        case certURI:
        case certIPAddress:
        case certRegisterID:
        break;
        default:
        intValue = 0;   /* force a break for anything else */
        }

        if (intValue == 0)
            break;
    
        if (namesList == NULL) {
            namesList = current = tail =
            PORT_ArenaZNew(arena, CERTGeneralName);
        } else {
            current = PORT_ArenaZNew(arena, CERTGeneralName);
        }
        if (current == NULL) {
            GEN_BREAK (SECFailure);
        }

        current->type = intValue;
        puts ("\nEnter data:");
        fflush (stdout);
        if (Gets_s (buffer, sizeof(buffer)) == NULL) {
            PORT_SetError(SEC_ERROR_INPUT_LEN);
            GEN_BREAK (SECFailure);
        }
        switch (current->type) {
        case certURI:
        case certDNSName:
        case certRFC822Name:
            current->name.other.data =
                PORT_ArenaAlloc (arena, strlen (buffer));
            if (current->name.other.data == NULL) {
                GEN_BREAK (SECFailure);
            }
            PORT_Memcpy(current->name.other.data, buffer,
                        current->name.other.len = strlen(buffer));
            break;

        case certEDIPartyName:
        case certIPAddress:
        case certOtherName:
        case certRegisterID:
        case certX400Address: {

            current->name.other.data =
                PORT_ArenaAlloc (arena, strlen (buffer) + 2);
            if (current->name.other.data == NULL) {
                GEN_BREAK (SECFailure);
            }
            
            PORT_Memcpy (current->name.other.data + 2, buffer,
                         strlen (buffer));
            /* This may not be accurate for all cases.  For now,
             * use this tag type */
            current->name.other.data[0] =
                (char)(((current->type - 1) & 0x1f)| 0x80);
            current->name.other.data[1] = (char)strlen (buffer);
            current->name.other.len = strlen (buffer) + 2;
            break;
        }

        case certDirectoryName: {
                CERTName *directoryName = NULL;
                
                directoryName = CERT_AsciiToName (buffer);
                if (!directoryName) {
                    fprintf(stderr, "certutil: improperly formatted name: "
                            "\"%s\"\n", buffer);
                    break;
                }
                
                rv = CERT_CopyName (arena, &current->name.directoryName,
                                    directoryName);
                CERT_DestroyName (directoryName);
                
                break;
            }
        }
        if (rv != SECSuccess)
            break;
        current->l.next = &(namesList->l);
        current->l.prev = &(tail->l);
        tail->l.next = &(current->l);
        tail = current;
        
    } while (1);

    if (rv != SECSuccess) {
        PORT_ArenaRelease (arena, mark);
        namesList = NULL;
    }
    return (namesList);
}

static SECStatus 
GetString(PRArenaPool *arena, char *prompt, SECItem *value)
{
    char buffer[251];
    char *buffPrt;

    buffer[0] = '\0';
    value->data = NULL;
    value->len = 0;
    
    puts (prompt);
    buffPrt = Gets_s (buffer, sizeof(buffer));
    /* returned NULL here treated the same way as empty string */
    if (buffPrt && strlen (buffer) > 0) {
        value->data = PORT_ArenaAlloc (arena, strlen (buffer));
        if (value->data == NULL) {
            PORT_SetError (SEC_ERROR_NO_MEMORY);
            return (SECFailure);
        }
        PORT_Memcpy (value->data, buffer, value->len = strlen(buffer));
    }
    return (SECSuccess);
}

static PRBool 
GetYesNo(char *prompt) 
{
    char buf[3];
    char *buffPrt;

    buf[0] = 'n';
    puts(prompt);
    buffPrt = Gets_s(buf, sizeof(buf));
    return (buffPrt && (buf[0] == 'y' || buf[0] == 'Y')) ? PR_TRUE : PR_FALSE;
}

static SECStatus 
AddKeyUsage (void *extHandle)
{
    SECItem bitStringValue;
    unsigned char keyUsage = 0x0;
    char buffer[5];
    int value;
    PRBool yesNoAns;

    while (1) {
        if (PrintChoicesAndGetAnswer(
                "\t\t0 - Digital Signature\n"
                "\t\t1 - Non-repudiation\n"
                "\t\t2 - Key encipherment\n"
                "\t\t3 - Data encipherment\n"   
                "\t\t4 - Key agreement\n"
                "\t\t5 - Cert signing key\n"   
                "\t\t6 - CRL signing key\n"
                "\t\tOther to finish\n",
                buffer, sizeof(buffer)) == SECFailure) {
            return SECFailure;
        }
        value = PORT_Atoi (buffer);
        if (value < 0 || value > 6)
            break;
        if (value == 0) {
            /* Checking that zero value of variable 'value'
             * corresponds to '0' input made by user */
            char *chPtr = strchr(buffer, '0');
            if (chPtr == NULL) {
                continue;
            }
        }
        keyUsage |= (0x80 >> value);
    }

    bitStringValue.data = &keyUsage;
    bitStringValue.len = 1;
    yesNoAns = GetYesNo("Is this a critical extension [y/N]?");

    return (CERT_EncodeAndAddBitStrExtension
            (extHandle, SEC_OID_X509_KEY_USAGE, &bitStringValue,
             yesNoAns));

}


static CERTOidSequence *
CreateOidSequence(void)
{
    CERTOidSequence *rv = (CERTOidSequence *)NULL;
    PRArenaPool *arena = (PRArenaPool *)NULL;

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if( (PRArenaPool *)NULL == arena ) {
        goto loser;
    }

    rv = (CERTOidSequence *)PORT_ArenaZNew(arena, CERTOidSequence);
    if( (CERTOidSequence *)NULL == rv ) {
        goto loser;
    }

    rv->oids = (SECItem **)PORT_ArenaZNew(arena, SECItem *);
    if( (SECItem **)NULL == rv->oids ) {
        goto loser;
    }

    rv->arena = arena;
    return rv;

loser:
    if( (PRArenaPool *)NULL != arena ) {
        PORT_FreeArena(arena, PR_FALSE);
    }

    return (CERTOidSequence *)NULL;
}

static void
DestroyOidSequence(CERTOidSequence *os)
{
    if (os->arena) {
        PORT_FreeArena(os->arena, PR_FALSE);
    }
}

static SECStatus
AddOidToSequence(CERTOidSequence *os, SECOidTag oidTag)
{
    SECItem **oids;
    PRUint32 count = 0;
    SECOidData *od;

    od = SECOID_FindOIDByTag(oidTag);
    if( (SECOidData *)NULL == od ) {
        return SECFailure;
    }

    for( oids = os->oids; (SECItem *)NULL != *oids; oids++ ) {
        count++;
    }

    /* ArenaZRealloc */

    {
        PRUint32 i;

        oids = (SECItem **)PORT_ArenaZNewArray(os->arena, SECItem *, count + 2);
        if( (SECItem **)NULL == oids ) {
            return SECFailure;
        }
    
        for( i = 0; i < count; i++ ) {
            oids[i] = os->oids[i];
        }

        /* ArenaZFree(os->oids); */
    }

    os->oids = oids;
    os->oids[count] = &od->oid;

    return SECSuccess;
}

SEC_ASN1_MKSUB(SEC_ObjectIDTemplate)

const SEC_ASN1Template CERT_OidSeqTemplate[] = {
    { SEC_ASN1_SEQUENCE_OF | SEC_ASN1_XTRN, offsetof(CERTOidSequence, oids),
      SEC_ASN1_SUB(SEC_ObjectIDTemplate) }
};


static SECItem *
EncodeOidSequence(CERTOidSequence *os)
{
    SECItem *rv;

    rv = (SECItem *)PORT_ArenaZNew(os->arena, SECItem);
    if( (SECItem *)NULL == rv ) {
        goto loser;
    }

    if( !SEC_ASN1EncodeItem(os->arena, rv, os, CERT_OidSeqTemplate) ) {
        goto loser;
    }

    return rv;

loser:
    return (SECItem *)NULL;
}

static SECStatus 
AddExtKeyUsage (void *extHandle)
{
    char buffer[5];
    int value;
    CERTOidSequence *os;
    SECStatus rv;
    SECItem *item;
    PRBool yesNoAns;

    os = CreateOidSequence();
    if( (CERTOidSequence *)NULL == os ) {
        return SECFailure;
    }

    while (1) {
        if (PrintChoicesAndGetAnswer(
                "\t\t0 - Server Auth\n"
                "\t\t1 - Client Auth\n"
                "\t\t2 - Code Signing\n"
                "\t\t3 - Email Protection\n"
                "\t\t4 - Timestamp\n"
                "\t\t5 - OCSP Responder\n"
                "\t\t6 - Step-up\n"
                "\t\tOther to finish\n",
                buffer, sizeof(buffer)) == SECFailure) {
            GEN_BREAK(SECFailure);
        }
        value = PORT_Atoi(buffer);

        if (value == 0) {
            /* Checking that zero value of variable 'value'
             * corresponds to '0' input made by user */
            char *chPtr = strchr(buffer, '0');
            if (chPtr == NULL) {
                continue;
            }
        }

        switch( value ) {
        case 0:
            rv = AddOidToSequence(os, SEC_OID_EXT_KEY_USAGE_SERVER_AUTH);
            break;
        case 1:
            rv = AddOidToSequence(os, SEC_OID_EXT_KEY_USAGE_CLIENT_AUTH);
            break;
        case 2:
            rv = AddOidToSequence(os, SEC_OID_EXT_KEY_USAGE_CODE_SIGN);
            break;
        case 3:
            rv = AddOidToSequence(os, SEC_OID_EXT_KEY_USAGE_EMAIL_PROTECT);
            break;
        case 4:
            rv = AddOidToSequence(os, SEC_OID_EXT_KEY_USAGE_TIME_STAMP);
            break;
        case 5:
            rv = AddOidToSequence(os, SEC_OID_OCSP_RESPONDER);
            break;
        case 6:
            rv = AddOidToSequence(os, SEC_OID_NS_KEY_USAGE_GOVT_APPROVED);
            break;
        default:
            goto endloop;
        }

        if( SECSuccess != rv ) goto loser;
    }

endloop:
    item = EncodeOidSequence(os);

    yesNoAns = GetYesNo("Is this a critical extension [y/N]?");

    rv = CERT_AddExtension(extHandle, SEC_OID_X509_EXT_KEY_USAGE, item,
                           yesNoAns, PR_TRUE);
    /*FALLTHROUGH*/
loser:
    DestroyOidSequence(os);
    return rv;
}

static SECStatus 
AddNscpCertType (void *extHandle)
{
    SECItem bitStringValue;
    unsigned char keyUsage = 0x0;
    char buffer[5];
    int value;
    PRBool yesNoAns;

    while (1) {
        if (PrintChoicesAndGetAnswer(
                "\t\t0 - SSL Client\n"
                "\t\t1 - SSL Server\n"
                "\t\t2 - S/MIME\n"
                "\t\t3 - Object Signing\n"   
                "\t\t4 - Reserved for future use\n"
                "\t\t5 - SSL CA\n"   
                "\t\t6 - S/MIME CA\n"
                "\t\t7 - Object Signing CA\n"
                "\t\tOther to finish\n",
                buffer, sizeof(buffer)) == SECFailure) {
            return SECFailure;
        }
        value = PORT_Atoi (buffer);
        if (value < 0 || value > 7)
            break;
        if (value == 0) {
            /* Checking that zero value of variable 'value'
             * corresponds to '0' input made by user */
            char *chPtr = strchr(buffer, '0');
            if (chPtr == NULL) {
                continue;
            }
        }
        keyUsage |= (0x80 >> value);
    }

    bitStringValue.data = &keyUsage;
    bitStringValue.len = 1;
    yesNoAns = GetYesNo("Is this a critical extension [y/N]?");

    return (CERT_EncodeAndAddBitStrExtension
            (extHandle, SEC_OID_NS_CERT_EXT_CERT_TYPE, &bitStringValue,
             yesNoAns));

}

static SECStatus 
AddSubjectAltNames(PRArenaPool *arena, CERTGeneralName **existingListp,
                   const char *names, CERTGeneralNameType type)
{
    CERTGeneralName *nameList = NULL;
    CERTGeneralName *current = NULL;
    PRCList *prev = NULL;
    const char *cp;
    char *tbuf;
    SECStatus rv = SECSuccess;


    /*
     * walk down the comma separated list of names. NOTE: there is
     * no sanity checks to see if the email address look like
     * email addresses.
     */
    for (cp=names; cp; cp = PORT_Strchr(cp,',')) {
        int len;
        char *end;

        if (*cp == ',') {
            cp++;
        }
        end = PORT_Strchr(cp,',');
        len = end ? end-cp : PORT_Strlen(cp);
        if (len <= 0) {
            continue;
        }
        tbuf = PORT_ArenaAlloc(arena,len+1);
        PORT_Memcpy(tbuf,cp,len);
        tbuf[len] = 0;
        current = (CERTGeneralName *) PORT_ZAlloc(sizeof(CERTGeneralName));
        if (!current) {
            rv = SECFailure;
            break;
        }
        if (prev) {
            current->l.prev = prev;
            prev->next = &(current->l);
        } else {
            nameList = current;
        }
        current->type = type;
        current->name.other.data = (unsigned char *)tbuf;
        current->name.other.len = PORT_Strlen(tbuf);
        prev = &(current->l);
    }
    /* at this point nameList points to the head of a doubly linked,
     * but not yet circular, list and current points to its tail. */
    if (rv == SECSuccess && nameList) {
        if (*existingListp != NULL) {
            PRCList *existingprev;
            /* add nameList to the end of the existing list */
            existingprev = (*existingListp)->l.prev;
            (*existingListp)->l.prev = &(current->l);
            nameList->l.prev = existingprev;
            existingprev->next = &(nameList->l);
            current->l.next = &((*existingListp)->l);
        }
        else {
            /* make nameList circular and set it as the new existingList */
            nameList->l.prev = prev;
            current->l.next = &(nameList->l);
            *existingListp = nameList;
        }
    }
    return rv;
}

static SECStatus 
AddEmailSubjectAlt(PRArenaPool *arena, CERTGeneralName **existingListp,
                   const char *emailAddrs)
{
    return AddSubjectAltNames(arena, existingListp, emailAddrs, 
                              certRFC822Name);
}

static SECStatus 
AddDNSSubjectAlt(PRArenaPool *arena, CERTGeneralName **existingListp,
                 const char *dnsNames)
{
    return AddSubjectAltNames(arena, existingListp, dnsNames, certDNSName);
}


static SECStatus 
AddBasicConstraint(void *extHandle)
{
    CERTBasicConstraints basicConstraint;    
    SECStatus rv;
    char buffer[10];
    PRBool yesNoAns;

    do {
        basicConstraint.pathLenConstraint = CERT_UNLIMITED_PATH_CONSTRAINT;
        basicConstraint.isCA = GetYesNo ("Is this a CA certificate [y/N]?");

        buffer[0] = '\0';
        if (PrintChoicesAndGetAnswer("Enter the path length constraint, "
                                     "enter to skip [<0 for unlimited path]:",
                                     buffer, sizeof(buffer)) == SECFailure) {
            GEN_BREAK(SECFailure);
        }
        if (PORT_Strlen (buffer) > 0)
            basicConstraint.pathLenConstraint = PORT_Atoi (buffer);

        yesNoAns = GetYesNo ("Is this a critical extension [y/N]?");

        rv = SECU_EncodeAndAddExtensionValue(NULL, extHandle,
         &basicConstraint, yesNoAns, SEC_OID_X509_BASIC_CONSTRAINTS,
         (EXTEN_EXT_VALUE_ENCODER)CERT_EncodeBasicConstraintValue);
    } while (0);

    return (rv);
}

static SECStatus 
AddAuthKeyID (void *extHandle)
{
    CERTAuthKeyID *authKeyID = NULL;    
    PRArenaPool *arena = NULL;
    SECStatus rv = SECSuccess;
    PRBool yesNoAns;

    do {
        arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
        if ( !arena ) {
            SECU_PrintError(progName, "out of memory");
            GEN_BREAK (SECFailure);
        }

        if (GetYesNo ("Enter value for the authKeyID extension [y/N]?") == 0)
            break;

        authKeyID = PORT_ArenaZNew(arena, CERTAuthKeyID);
        if (authKeyID == NULL) {
            GEN_BREAK (SECFailure);
        }

        rv = GetString (arena, "Enter value for the key identifier fields,"
                        "enter to omit:", &authKeyID->keyID);
        if (rv != SECSuccess)
            break;

        SECU_SECItemHexStringToBinary(&authKeyID->keyID);

        authKeyID->authCertIssuer = GetGeneralName (arena);
        if (authKeyID->authCertIssuer == NULL && 
            SECFailure == PORT_GetError ())
            break;


        rv = GetString (arena, "Enter value for the authCertSerial field, "
                        "enter to omit:", &authKeyID->authCertSerialNumber);

        yesNoAns = GetYesNo ("Is this a critical extension [y/N]?");

        rv = SECU_EncodeAndAddExtensionValue(arena, extHandle,
             authKeyID, yesNoAns, SEC_OID_X509_AUTH_KEY_ID, 
             (EXTEN_EXT_VALUE_ENCODER) CERT_EncodeAuthKeyID);
        if (rv)
            break;

    } while (0);
    if (arena)
        PORT_FreeArena (arena, PR_FALSE);
    return (rv);
}   
    
static SECStatus 
AddSubjKeyID (void *extHandle)
{
    SECItem keyID;
    PRArenaPool *arena = NULL;
    SECStatus rv = SECSuccess;
    PRBool yesNoAns;

    do {
        arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
        if ( !arena ) {
            SECU_PrintError(progName, "out of memory");
            GEN_BREAK (SECFailure);
        }
        printf("Adding Subject Key ID extension.\n");

        rv = GetString (arena, "Enter value for the key identifier fields,"
                        "enter to omit:", &keyID);
        if (rv != SECSuccess)
            break;

        SECU_SECItemHexStringToBinary(&keyID);

        yesNoAns = GetYesNo ("Is this a critical extension [y/N]?");

        rv = SECU_EncodeAndAddExtensionValue(arena, extHandle,
             &keyID, yesNoAns, SEC_OID_X509_SUBJECT_KEY_ID, 
             (EXTEN_EXT_VALUE_ENCODER) CERT_EncodeSubjectKeyID);
        if (rv)
            break;

    } while (0);
    if (arena)
        PORT_FreeArena (arena, PR_FALSE);
    return (rv);
}   

static SECStatus 
AddCrlDistPoint(void *extHandle)
{
    PRArenaPool *arena = NULL;
    CERTCrlDistributionPoints *crlDistPoints = NULL;
    CRLDistributionPoint *current;
    SECStatus rv = SECSuccess;
    int count = 0, intValue;
    char buffer[512];

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if ( !arena )
        return (SECFailure);

    do {
        current = NULL;

        current = PORT_ArenaZNew(arena, CRLDistributionPoint);
        if (current == NULL) {
            GEN_BREAK (SECFailure);
        }   

        /* Get the distributionPointName fields - this field is optional */
        if (PrintChoicesAndGetAnswer(
                "Enter the type of the distribution point name:\n"
                "\t1 - Full Name\n\t2 - Relative Name\n\tAny other "
                "number to finish\n\t\tChoice: ",
                buffer, sizeof(buffer)) == SECFailure) {
        GEN_BREAK (SECFailure);
    }
        intValue = PORT_Atoi (buffer);
        switch (intValue) {
        case generalName:
            current->distPointType = intValue;
            current->distPoint.fullName = GetGeneralName (arena);
            rv = PORT_GetError();
            break;

        case relativeDistinguishedName: {
            CERTName *name;

            current->distPointType = intValue;
            puts ("Enter the relative name: ");
            fflush (stdout);
            if (Gets_s (buffer, sizeof(buffer)) == NULL) {
                GEN_BREAK (SECFailure);
            }
            /* For simplicity, use CERT_AsciiToName to converse from a string
               to NAME, but we only interest in the first RDN */
            name = CERT_AsciiToName (buffer);
            if (!name) {
                GEN_BREAK (SECFailure);
            }
            rv = CERT_CopyRDN (arena, &current->distPoint.relativeName,
                               name->rdns[0]);
            CERT_DestroyName (name);
            break;
          }
        }
        if (rv != SECSuccess)
            break;

        /* Get the reason flags */
        if (PrintChoicesAndGetAnswer(
                "\nSelect one of the following for the reason flags\n"
                "\t0 - unused\n\t1 - keyCompromise\n"
                "\t2 - caCompromise\n\t3 - affiliationChanged\n"
                "\t4 - superseded\n\t5 - cessationOfOperation\n"
                "\t6 - certificateHold\n"
                "\tAny other number to finish\t\tChoice: ",
                buffer, sizeof(buffer)) == SECFailure) {
            GEN_BREAK(SECFailure);
        }
        intValue = PORT_Atoi (buffer);
        if (intValue == 0) {
            /* Checking that zero value of variable 'value'
             * corresponds to '0' input made by user */
            char *chPtr = strchr(buffer, '0');
            if (chPtr == NULL) {
                intValue = -1;
            }
        }
        if (intValue >= 0 && intValue <8) {
            current->reasons.data = PORT_ArenaAlloc (arena, sizeof(char));
            if (current->reasons.data == NULL) {
                GEN_BREAK (SECFailure);
            }
            *current->reasons.data = (char)(0x80 >> intValue);
            current->reasons.len = 1;
        }
        puts ("Enter value for the CRL Issuer name:\n");
        current->crlIssuer = GetGeneralName (arena);
        if (current->crlIssuer == NULL && (rv = PORT_GetError()) == SECFailure)
            break;

        if (crlDistPoints == NULL) {
            crlDistPoints = PORT_ArenaZNew(arena, CERTCrlDistributionPoints);
            if (crlDistPoints == NULL) {
                GEN_BREAK (SECFailure);
            }
        }

        crlDistPoints->distPoints =
            PORT_ArenaGrow (arena, crlDistPoints->distPoints,
                            sizeof (*crlDistPoints->distPoints) * count,
                            sizeof (*crlDistPoints->distPoints) *(count + 1));
        if (crlDistPoints->distPoints == NULL) {
            GEN_BREAK (SECFailure);
        }

        crlDistPoints->distPoints[count] = current;
        ++count;
        if (GetYesNo("Enter another value for the CRLDistributionPoint "
                      "extension [y/N]?") == 0) {
            /* Add null to the end to mark end of data */
            crlDistPoints->distPoints =
                PORT_ArenaGrow(arena, crlDistPoints->distPoints,
               sizeof (*crlDistPoints->distPoints) * count,
               sizeof (*crlDistPoints->distPoints) *(count + 1));
            crlDistPoints->distPoints[count] = NULL;    
            break;
        }


    } while (1);
    
    if (rv == SECSuccess) {
        PRBool yesNoAns = GetYesNo ("Is this a critical extension [y/N]?");

        rv = SECU_EncodeAndAddExtensionValue(arena, extHandle,
         crlDistPoints, yesNoAns, SEC_OID_X509_CRL_DIST_POINTS,
         (EXTEN_EXT_VALUE_ENCODER)CERT_EncodeCRLDistributionPoints);
    }
    if (arena)
        PORT_FreeArena (arena, PR_FALSE);
    return (rv);
}



static SECStatus 
AddPolicyConstraints(void *extHandle)
{
    CERTCertificatePolicyConstraints *policyConstr;
    PRArenaPool *arena = NULL;
    SECStatus rv = SECSuccess;
    SECItem *item, *dummy;
    char buffer[512];
    int value;
    PRBool yesNoAns;
    PRBool skipExt = PR_TRUE;

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if ( !arena ) {
        SECU_PrintError(progName, "out of memory");
        return SECFailure;
    }

    policyConstr = PORT_ArenaZNew(arena, CERTCertificatePolicyConstraints);
    if (policyConstr == NULL) {
        SECU_PrintError(progName, "out of memory");
        goto loser;
    }

    if (PrintChoicesAndGetAnswer("for requireExplicitPolicy enter the number "
               "of certs in path\nbefore explicit policy is required\n"
               "(press Enter to omit)", buffer, sizeof(buffer)) == SECFailure) {
        goto loser;
    }

    if (PORT_Strlen(buffer)) {
        value = PORT_Atoi(buffer);
    if (value < 0) {
            goto loser;
        }
        item = &policyConstr->explicitPolicySkipCerts;
        dummy = SEC_ASN1EncodeInteger(arena, item, value);
        if (!dummy) {
            goto loser;
        }
        skipExt = PR_FALSE;
    }

    if (PrintChoicesAndGetAnswer("for inihibitPolicyMapping enter "
               "the number of certs in path\n"
           "after which policy mapping is not allowed\n"
               "(press Enter to omit)", buffer, sizeof(buffer)) == SECFailure) {
        goto loser;
    }

    if (PORT_Strlen(buffer)) {
        value = PORT_Atoi(buffer);
    if (value < 0) {
            goto loser;
        }
        item = &policyConstr->inhibitMappingSkipCerts;
        dummy = SEC_ASN1EncodeInteger(arena, item, value);
        if (!dummy) {
            goto loser;
        }
        skipExt = PR_FALSE;
    }
 
    
    if (!skipExt) {
        yesNoAns = GetYesNo("Is this a critical extension [y/N]?");

        rv = SECU_EncodeAndAddExtensionValue(arena, extHandle, policyConstr,
         yesNoAns, SEC_OID_X509_POLICY_CONSTRAINTS,
         (EXTEN_EXT_VALUE_ENCODER)CERT_EncodePolicyConstraintsExtension);
    } else {
        fprintf(stdout, "Policy Constraint extensions must contain "
                        "at least one policy field\n");
        rv = SECFailure;
    }
   
loser:
    if (arena) {
        PORT_FreeArena (arena, PR_FALSE);
    }
    return (rv);
}


static SECStatus 
AddInhibitAnyPolicy(void *extHandle)
{
    CERTCertificateInhibitAny certInhibitAny;
    PRArenaPool *arena = NULL;
    SECStatus rv = SECSuccess;
    SECItem *item, *dummy;
    char buffer[10];
    int value;
    PRBool yesNoAns;
    

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if ( !arena ) {
        SECU_PrintError(progName, "out of memory");
        return SECFailure;
    }

    if (PrintChoicesAndGetAnswer("Enter the number of certs in the path "
                                 "permitted to use anyPolicy.\n"
                                 "(press Enter for 0)",
                                 buffer, sizeof(buffer)) == SECFailure) {
        goto loser;
    }

    item = &certInhibitAny.inhibitAnySkipCerts;
    value = PORT_Atoi(buffer);
    if (value < 0) {
        goto loser;
    }
    dummy = SEC_ASN1EncodeInteger(arena, item, value);
    if (!dummy) {
        goto loser;
    }
    
    yesNoAns = GetYesNo("Is this a critical extension [y/N]?");
    
    rv = SECU_EncodeAndAddExtensionValue(arena, extHandle, &certInhibitAny,
         yesNoAns, SEC_OID_X509_INHIBIT_ANY_POLICY,
         (EXTEN_EXT_VALUE_ENCODER)CERT_EncodeInhibitAnyExtension);
loser:
    if (arena) {
        PORT_FreeArena (arena, PR_FALSE);
    }
    return (rv);
}


static SECStatus 
AddPolicyMappings(void *extHandle)
{
    CERTPolicyMap **policyMapArr = NULL;
    CERTPolicyMap *current;
    PRArenaPool *arena = NULL;
    SECStatus rv = SECSuccess;
    int count = 0;
    char buffer[512];
    
    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if ( !arena ) {
        SECU_PrintError(progName, "out of memory");
        return SECFailure;
    }

    do {
        if (PrintChoicesAndGetAnswer("Enter an Object Identifier (dotted "
                                     "decimal format) for Issuer Domain Policy",
                                     buffer, sizeof(buffer)) == SECFailure) {
            GEN_BREAK (SECFailure);
        }

        current = PORT_ArenaZNew(arena, CERTPolicyMap);
        if (current == NULL) {
            GEN_BREAK(SECFailure);
        }

        rv = SEC_StringToOID(arena, &current->issuerDomainPolicy, buffer, 0);
        if (rv == SECFailure) {
            GEN_BREAK(SECFailure);
        }

        if (PrintChoicesAndGetAnswer("Enter an Object Identifier for "
                                     "Subject Domain Policy",
                                     buffer, sizeof(buffer)) == SECFailure) {
            GEN_BREAK (SECFailure);
        }

        rv = SEC_StringToOID(arena, &current->subjectDomainPolicy, buffer, 0);
        if (rv == SECFailure) {
            GEN_BREAK(SECFailure);
        }

        if (policyMapArr == NULL) {
            policyMapArr = PORT_ArenaZNew(arena, CERTPolicyMap *);
            if (policyMapArr == NULL) {
                GEN_BREAK (SECFailure);
            }
        }

        policyMapArr = PORT_ArenaGrow(arena, policyMapArr,
                                         sizeof (current) * count,
                                         sizeof (current) *(count + 1));
        if (policyMapArr == NULL) {
            GEN_BREAK (SECFailure);
        }
    
        policyMapArr[count] = current;
        ++count;
        
        if (!GetYesNo("Enter another Policy Mapping [y/N]")) {
            /* Add null to the end to mark end of data */
            policyMapArr = PORT_ArenaGrow (arena, policyMapArr,
                                           sizeof (current) * count,
                                           sizeof (current) *(count + 1));
            if (policyMapArr == NULL) {
                GEN_BREAK (SECFailure);
            }
            policyMapArr[count] = NULL;        
            break;
        }

    } while (1);

    if (rv == SECSuccess) {
        CERTCertificatePolicyMappings mappings;
        PRBool yesNoAns = GetYesNo("Is this a critical extension [y/N]?");

        mappings.arena = arena;
        mappings.policyMaps = policyMapArr;
        rv = SECU_EncodeAndAddExtensionValue(arena, extHandle, &mappings,
         yesNoAns, SEC_OID_X509_POLICY_MAPPINGS,
         (EXTEN_EXT_VALUE_ENCODER)CERT_EncodePolicyMappingExtension);
    }
    if (arena)
        PORT_FreeArena (arena, PR_FALSE);
    return (rv);
}

enum PoliciQualifierEnum {
    cpsPointer = 1,
    userNotice = 2
};

static CERTPolicyQualifier **
RequestPolicyQualifiers(PRArenaPool *arena, SECItem *policyID)
{
    CERTPolicyQualifier **policyQualifArr = NULL;
    CERTPolicyQualifier *current;
    SECStatus rv = SECSuccess;
    int count = 0;
    char buffer[512];
    void *mark;
    SECOidData *oid = NULL;
    int intValue = 0;
    int inCount = 0;

    PORT_Assert(arena);
    mark = PORT_ArenaMark(arena);
    do {
        current = PORT_ArenaZNew(arena, CERTPolicyQualifier);
        if (current == NULL) {
            GEN_BREAK(SECFailure);
        }

        /* Get the accessMethod fields */
        SECU_PrintObjectID(stdout, policyID,
                           "Choose the type of qualifier for policy" , 0);

        if (PrintChoicesAndGetAnswer(
                "\t1 - CPS Pointer qualifier\n"
                "\t2 - User notice qualifier\n"
                "\tAny other number to finish\n"
                "\t\tChoice: ", buffer, sizeof(buffer)) == SECFailure) {
            GEN_BREAK (SECFailure);
        }
        intValue = PORT_Atoi(buffer);
        switch (intValue) {
        case cpsPointer: {
            SECItem input;

            oid = SECOID_FindOIDByTag(SEC_OID_PKIX_CPS_POINTER_QUALIFIER);
            if (PrintChoicesAndGetAnswer("Enter CPS pointer URI: ",
                     buffer, sizeof(buffer)) == SECFailure) {
                GEN_BREAK (SECFailure);
            }
            input.len = PORT_Strlen(buffer);
            input.data = (void*)PORT_ArenaStrdup(arena, buffer);
            if (input.data == NULL ||
            SEC_ASN1EncodeItem(arena, &current->qualifierValue, &input,
                   SEC_ASN1_GET(SEC_IA5StringTemplate)) == NULL) {
                GEN_BREAK (SECFailure);
            }
            break;
        }
        case userNotice: {
            SECItem **noticeNumArr;
            CERTUserNotice *notice = PORT_ArenaZNew(arena, CERTUserNotice);
            if (!notice) {
                GEN_BREAK(SECFailure);
            }
            
            oid = SECOID_FindOIDByTag(SEC_OID_PKIX_USER_NOTICE_QUALIFIER);

            if (GetYesNo("\t add a User Notice reference? [y/N]")) {

                if (PrintChoicesAndGetAnswer("Enter user organization string: ",
                 buffer, sizeof(buffer)) == SECFailure) {
                    GEN_BREAK (SECFailure);
                }

                notice->noticeReference.organization.type = siAsciiString;
                notice->noticeReference.organization.len =
                    PORT_Strlen(buffer);
                notice->noticeReference.organization.data =
                    (void*)PORT_ArenaStrdup(arena, buffer);


                noticeNumArr = PORT_ArenaZNewArray(arena, SECItem *, 2);
                if (!noticeNumArr) {
                    GEN_BREAK (SECFailure);
                }
                
                do {
                    SECItem *noticeNum;
                    
                    noticeNum = PORT_ArenaZNew(arena, SECItem);
                    
                    if (PrintChoicesAndGetAnswer(
                      "Enter User Notice reference number "
                      "(or -1 to quit): ",
                                      buffer, sizeof(buffer)) == SECFailure) {
                        GEN_BREAK (SECFailure);
                    }
                    
                    intValue = PORT_Atoi(buffer);
                    if (noticeNum == NULL) {
                        if (intValue < 0) {
                            fprintf(stdout, "a noticeReference must have at "
                                    "least one reference number\n");
                            GEN_BREAK (SECFailure);
                        }
                    } else {
                        if (intValue >= 0) {
                            noticeNumArr = PORT_ArenaGrow(arena, noticeNumArr,
                          sizeof (current) * inCount,
                          sizeof (current) *(inCount + 1));
                            if (noticeNumArr == NULL) {
                                GEN_BREAK (SECFailure);
                            }
                        } else {
                            break;
                        }
                    }
                    if (!SEC_ASN1EncodeInteger(arena, noticeNum, intValue)) {
                        GEN_BREAK (SECFailure);
                    }
                    noticeNumArr[inCount++] = noticeNum;
                    noticeNumArr[inCount] = NULL;
                    
                } while (1);
                if (rv == SECFailure) {
                    GEN_BREAK(SECFailure);
                }
                notice->noticeReference.noticeNumbers = noticeNumArr;
                rv = CERT_EncodeNoticeReference(arena, &notice->noticeReference,
                                                &notice->derNoticeReference);
                if (rv == SECFailure) {
                    GEN_BREAK(SECFailure);
                }
            }
            if (GetYesNo("\t EnterUser Notice explicit text? [y/N]")) {
                /* Getting only 200 bytes - RFC limitation */
                if (PrintChoicesAndGetAnswer(
                        "\t", buffer, 200) == SECFailure) {
                        GEN_BREAK (SECFailure);
                }
                notice->displayText.type = siAsciiString;
                notice->displayText.len = PORT_Strlen(buffer);
                notice->displayText.data = 
                                (void*)PORT_ArenaStrdup(arena, buffer);
        if (notice->displayText.data == NULL) {
            GEN_BREAK(SECFailure);
        }
            }

            rv = CERT_EncodeUserNotice(arena, notice, &current->qualifierValue);
            if (rv == SECFailure) {
                GEN_BREAK(SECFailure);
            }

            break;
        }
        }
        if (rv == SECFailure || oid == NULL ||
            SECITEM_CopyItem(arena, &current->qualifierID, &oid->oid) 
            == SECFailure) {
            GEN_BREAK (SECFailure);
        }

        if (!policyQualifArr) {
            policyQualifArr = PORT_ArenaZNew(arena, CERTPolicyQualifier *);
        } else {
            policyQualifArr = PORT_ArenaGrow (arena, policyQualifArr,
                                         sizeof (current) * count,
                                         sizeof (current) *(count + 1));
        }
        if (policyQualifArr == NULL) {
            GEN_BREAK (SECFailure);
        }
    
        policyQualifArr[count] = current;
        ++count;

        if (!GetYesNo ("Enter another policy qualifier [y/N]")) {
            /* Add null to the end to mark end of data */
            policyQualifArr = PORT_ArenaGrow(arena, policyQualifArr,
                                              sizeof (current) * count,
                                              sizeof (current) *(count + 1));
            if (policyQualifArr == NULL) {
                GEN_BREAK (SECFailure);
            }
            policyQualifArr[count] = NULL;        
            break;
        }

    } while (1);

    if (rv != SECSuccess) {
        PORT_ArenaRelease (arena, mark);
        policyQualifArr = NULL;
    }
    return (policyQualifArr);
}

static SECStatus 
AddCertPolicies(void *extHandle)
{
    CERTPolicyInfo **certPoliciesArr = NULL;
    CERTPolicyInfo *current;
    PRArenaPool *arena = NULL;
    SECStatus rv = SECSuccess;
    int count = 0;
    char buffer[512];

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if ( !arena ) {
        SECU_PrintError(progName, "out of memory");
        return SECFailure;
    }

    do {
        current = PORT_ArenaZNew(arena, CERTPolicyInfo);
        if (current == NULL) {
            GEN_BREAK(SECFailure);
        }

        if (PrintChoicesAndGetAnswer("Enter a CertPolicy Object Identifier "
                                     "(dotted decimal format)\n"
                                     "or \"any\" for AnyPolicy:",
                                     buffer, sizeof(buffer)) == SECFailure) {
            GEN_BREAK (SECFailure);
        }
    
        if (strncmp(buffer, "any", 3) == 0) {
            /* use string version of X509_CERTIFICATE_POLICIES.anyPolicy */
            strcpy(buffer, "OID.2.5.29.32.0");
        }
        rv = SEC_StringToOID(arena, &current->policyID, buffer, 0);

        if (rv == SECFailure) {
            GEN_BREAK(SECFailure);
        }
        
        current->policyQualifiers = 
            RequestPolicyQualifiers(arena, &current->policyID); 

        if (!certPoliciesArr) {
            certPoliciesArr = PORT_ArenaZNew(arena, CERTPolicyInfo *);
        } else {
        certPoliciesArr = PORT_ArenaGrow(arena, certPoliciesArr,
                                         sizeof (current) * count,
                                         sizeof (current) *(count + 1));
        }
        if (certPoliciesArr == NULL) {
            GEN_BREAK (SECFailure);
        }
    
        certPoliciesArr[count] = current;
        ++count;
        
        if (!GetYesNo ("Enter another PolicyInformation field [y/N]?")) {
            /* Add null to the end to mark end of data */
            certPoliciesArr = PORT_ArenaGrow(arena, certPoliciesArr,
                                              sizeof (current) * count,
                                              sizeof (current) *(count + 1));
            if (certPoliciesArr == NULL) {
                GEN_BREAK (SECFailure);
            }
            certPoliciesArr[count] = NULL;        
            break;
        }

    } while (1);

    if (rv == SECSuccess) {
        CERTCertificatePolicies policies;
        PRBool yesNoAns = GetYesNo("Is this a critical extension [y/N]?");

        policies.arena = arena;
        policies.policyInfos = certPoliciesArr;
        
        rv = SECU_EncodeAndAddExtensionValue(arena, extHandle, &policies,
         yesNoAns, SEC_OID_X509_CERTIFICATE_POLICIES,
         (EXTEN_EXT_VALUE_ENCODER)CERT_EncodeCertPoliciesExtension);
    }
    if (arena)
    PORT_FreeArena(arena, PR_FALSE);
    return (rv);
}

enum AuthInfoAccessTypesEnum {
    caIssuers = 1,
    ocsp = 2
};

enum SubjInfoAccessTypesEnum {
    caRepository = 1,
    timeStamping = 2
};

/* Encode and add an AIA or SIA extension */
static SECStatus 
AddInfoAccess(void *extHandle, PRBool addSIAExt, PRBool isCACert)
{
    CERTAuthInfoAccess **infoAccArr = NULL;
    CERTAuthInfoAccess *current;
    PRArenaPool *arena = NULL;
    SECStatus rv = SECSuccess;
    int count = 0;
    char buffer[512];
    SECOidData *oid = NULL;
    int intValue = 0;

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if ( !arena ) {
        SECU_PrintError(progName, "out of memory");
        return SECFailure;
    }

    do {
        current = NULL;
        current = PORT_ArenaZNew(arena, CERTAuthInfoAccess);
        if (current == NULL) {
            GEN_BREAK(SECFailure);
        }

        /* Get the accessMethod fields */
        if (addSIAExt) {
            if (isCACert) {
                puts("Adding \"CA Repository\" access method type for "
                    "Subject Information Access extension:\n");
                intValue = caRepository;
            } else {
                puts("Adding \"Time Stamping Services\" access method type for "
                    "Subject Information Access extension:\n");
                intValue = timeStamping;
            }
        } else {
            PrintChoicesAndGetAnswer("Enter access method type "
                "for Authority Information Access extension:\n"
                "\t1 - CA Issuers\n\t2 - OCSP\n\tAny"
                "other number to finish\n\tChoice",
                buffer, sizeof(buffer));
            intValue = PORT_Atoi(buffer);
        }
        if (addSIAExt) {
            switch (intValue) {
              case caRepository:
                  oid = SECOID_FindOIDByTag(SEC_OID_PKIX_CA_REPOSITORY);
                  break;
                  
              case timeStamping:
                  oid = SECOID_FindOIDByTag(SEC_OID_PKIX_TIMESTAMPING);
                  break;
            } 
        } else {
            switch (intValue) {
              case caIssuers:
                  oid = SECOID_FindOIDByTag(SEC_OID_PKIX_CA_ISSUERS);
                  break;
                  
              case ocsp:
                  oid = SECOID_FindOIDByTag(SEC_OID_PKIX_OCSP);
                  break;
            } 
        }
        if (oid == NULL ||
            SECITEM_CopyItem(arena, &current->method, &oid->oid) 
            == SECFailure) {
            GEN_BREAK (SECFailure);
        }

        current->location = GetGeneralName(arena);
        if (!current->location) {
            GEN_BREAK(SECFailure);
        }
       
        if (infoAccArr == NULL) {
            infoAccArr = PORT_ArenaZNew(arena, CERTAuthInfoAccess *);
        } else {
            infoAccArr = PORT_ArenaGrow(arena, infoAccArr,
                                     sizeof (current) * count,
                                     sizeof (current) *(count + 1));
        }
        if (infoAccArr == NULL) {
            GEN_BREAK (SECFailure);
        }
    
        infoAccArr[count] = current;
        ++count;
        
        PR_snprintf(buffer, sizeof(buffer), "Add another location to the %s"
                    " Information Access extension [y/N]",
                    (addSIAExt) ? "Subject" : "Authority");

        if (GetYesNo (buffer) == 0) {
            /* Add null to the end to mark end of data */
            infoAccArr = PORT_ArenaGrow(arena, infoAccArr,
                                         sizeof (current) * count,
                                         sizeof (current) *(count + 1));
            if (infoAccArr == NULL) {
                GEN_BREAK (SECFailure);
            }
            infoAccArr[count] = NULL;        
            break;
        }

    } while (1);

    if (rv == SECSuccess) {
        int oidIdent = SEC_OID_X509_AUTH_INFO_ACCESS;

        PRBool yesNoAns = GetYesNo("Is this a critical extension [y/N]?");
        
        if (addSIAExt) {
            oidIdent = SEC_OID_X509_SUBJECT_INFO_ACCESS;
        }
        rv = SECU_EncodeAndAddExtensionValue(arena, extHandle, infoAccArr,
         yesNoAns, oidIdent,
         (EXTEN_EXT_VALUE_ENCODER)CERT_EncodeInfoAccessExtension);
    }
    if (arena)
        PORT_FreeArena(arena, PR_FALSE);
    return (rv);
}

SECStatus
AddExtensions(void *extHandle, const char *emailAddrs, const char *dnsNames,
              certutilExtnList extList)
{
    SECStatus rv = SECSuccess;
    char *errstring = NULL;
    
    do {
        /* Add key usage extension */
        if (extList[ext_keyUsage]) {
            rv = AddKeyUsage(extHandle);
            if (rv) {
                errstring = "KeyUsage";
                break;
            }
        }

        /* Add extended key usage extension */
        if (extList[ext_extKeyUsage]) {
            rv = AddExtKeyUsage(extHandle);
            if (rv) {
                errstring = "ExtendedKeyUsage";
                break;
            }
        }

        /* Add basic constraint extension */
        if (extList[ext_basicConstraint]) {
            rv = AddBasicConstraint(extHandle);
            if (rv) {
                errstring = "BasicConstraint";
                break;
            }
        }

        if (extList[ext_authorityKeyID]) {
            rv = AddAuthKeyID(extHandle);
            if (rv) {
                errstring = "AuthorityKeyID";
                break;
            }
        }

        if (extList[ext_subjectKeyID]) {
            rv = AddSubjKeyID(extHandle);
            if (rv) {
                errstring = "SubjectKeyID";
                break;
            }
        }    

        if (extList[ext_CRLDistPts]) {
            rv = AddCrlDistPoint(extHandle);
            if (rv) {
                errstring = "CRLDistPoints";
                break;
            }
        }

        if (extList[ext_NSCertType]) {
            rv = AddNscpCertType(extHandle);
            if (rv) {
                errstring = "NSCertType";
                break;
            }
        }

        if (extList[ext_authInfoAcc] || extList[ext_subjInfoAcc]) {
            rv = AddInfoAccess(extHandle, extList[ext_subjInfoAcc],
                           extList[ext_basicConstraint]);
            if (rv) {
                errstring = "InformationAccess";
                break;
            }
        }

        if (extList[ext_certPolicies]) {
            rv = AddCertPolicies(extHandle);
            if (rv) {
                errstring = "Policies";
                break;
            }
        }

        if (extList[ext_policyMappings]) {
            rv = AddPolicyMappings(extHandle);
            if (rv) {
                errstring = "PolicyMappings";
                break;
            }
        }

        if (extList[ext_policyConstr]) {
            rv = AddPolicyConstraints(extHandle);
            if (rv) {
                errstring = "PolicyConstraints";
                break;
            }
        }

        if (extList[ext_inhibitAnyPolicy]) {
            rv = AddInhibitAnyPolicy(extHandle);
            if (rv) {
                errstring = "InhibitAnyPolicy";
                break;
            }
        }

        if (emailAddrs || dnsNames) {
            PRArenaPool *arena;
            CERTGeneralName *namelist = NULL;
            SECItem item = { 0, NULL, 0 };
            
            arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
            if (arena == NULL) {
                rv = SECFailure;
                break;
            }

            rv = AddEmailSubjectAlt(arena, &namelist, emailAddrs);

            rv |= AddDNSSubjectAlt(arena, &namelist, dnsNames);

            if (rv == SECSuccess) {
                rv = CERT_EncodeAltNameExtension(arena, namelist, &item);
            if (rv == SECSuccess) {
                    rv = CERT_AddExtension(extHandle,
                                          SEC_OID_X509_SUBJECT_ALT_NAME,
                                          &item, PR_FALSE, PR_TRUE);
        }
            }
        PORT_FreeArena(arena, PR_FALSE);
        if (rv) {
                errstring = "SubjectAltName";
                break;
        }
        }
    } while (0);
    
    if (rv != SECSuccess) {
        SECU_PrintError(progName, "Problem creating %s extension", errstring);
    }
    return rv;
}
