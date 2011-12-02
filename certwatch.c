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


/* $Id: certwatch.c,v 1.12 2009/10/09 17:08:18 dgregor Exp $ */

/* Certificate expiry warning generation code, based on code from
 * Stronghold.  Joe Orton <jorton@redhat.com> */

/* Replaced usage of OpenSSL with NSS.
 * Elio Maldonado <emaldona@redhat.com> */

#include <nspr.h>
#include <nss.h>
#include <cert.h>
#include <certt.h>
#include <prlong.h>
#include <prtime.h>
#include <pk11func.h>
#include <assert.h>
#include <secmod.h>
#include <base64.h>
#include <seccomon.h>
#include <certt.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>

#define TIME_BUF_SIZE 100

/* Return a certificate structure from a pem-encoded cert in a file;
 * or NULL on failure. Semantics similar to the OpenSSL call
 * PEM_read_X509(fp, NULL, NULL, NULL);
 */
extern CERTCertificate *
PEMUTIL_PEM_read_X509(const char *filename);

/* size big enough for formatting time buffer */
#define TIME_SIZE 30

static int warn_period = 30;
static char *warn_address = "root";

/* Uses the password passed in the -f(pwfile) argument of the command line.
 * After use once, null it out otherwise PKCS11 calls us forever.?
 *
 * Code based on SECU_GetModulePassword from the Mozilla NSS secutils
 * internal library.
 */
static char *GetModulePassword(PK11SlotInfo *slot, PRBool retry, void *arg)
{
    int i;
    unsigned char phrase[200];
    PRFileDesc *fd;
    PRInt32 nb;
    char *pwFile = arg;

    if (!pwFile) return 0;
    if (retry) return 0; /* no good retrying - file contents will be the same */
    if (!(fd = PR_Open(pwFile, PR_RDONLY, 0))) return 0;

    nb = PR_Read(fd, phrase, sizeof(phrase));
    PR_Close(fd);

    /* handle the Windows EOL case */
    i = 0;
    while (phrase[i] != '\r' && phrase[i] != '\n' && i < nb) i++;
    phrase[i] = '\0';
    if (nb == 0) return NULL;

    return (char*) PORT_Strdup((char*)phrase);
}

/* Format a PRTime value into a buffer with format "%a %b %d %H:%M:%S %Y";
 * semantics are those of ctime_r(). */
char *pr_ctime(PRTime time, char *buf, int size)
{
    PRUint32 bytesCopied;
    PRExplodedTime et;
    PR_ExplodeTime(time, PR_GMTParameters, &et);
    bytesCopied = PR_FormatTime(buf, size, "%a %b %d %H:%M:%S %Y", &et);
    if (!bytesCopied) return NULL;
    return buf;
}

/* Computes the day difference among two PRTime's */
static int diff_time_days(PRTime aT, PRTime bT)
{
    /* Dividing before substracting to support the desired granularity */
    PRInt64 secs = (aT/PR_USEC_PER_SEC - bT/PR_USEC_PER_SEC);
    return secs / 86400L;
}

/* Print a warning message that the certificate in 'filename', issued
 * to hostname 'hostname', will expire (or has expired). */
static int warning(FILE *out, const char *filename, const char *hostname,
                   SECCertTimeValidity validity,
                   PRTime start, PRTime end, PRTime now, int quiet)
{
    /* Note that filename can be the cert nickname. */
    int renew = 1, days;         /* days till expiry */
    char subj[50];

    switch (validity) {
    case secCertTimeNotValidYet:
        strcpy(subj, "is not yet valid");
        renew = 0;
        break;
    case secCertTimeExpired:
        sprintf(subj, "has expired");
        break;
    case secCertTimeValid:
        days = diff_time_days(end, now);
        if (days == 0) {
            strcpy(subj, "will expire today");
        } else if (days == 1) {
            sprintf(subj, "will expire tomorrow");
        } else if (days < warn_period) {
            sprintf(subj, "will expire in %d days", days);
        } else {
            return 0; /* nothing to warn about. */
        }
        break;
    case secCertTimeUndetermined:
    default:
        /* it will never get here if caller checks validity */
        strcpy(subj, "validity could not be decoded from the cert");
        renew = 0;
        break;
    }

    if (quiet) return 1;

    fprintf(out, "To: %s\n", warn_address);
    fprintf(out, "Subject: The certificate for %s %s\n", hostname, subj);
    fputs("\n", out);

    fprintf(out,
            " ################# SSL Certificate Warning ################\n\n");

    fprintf(out,
            "  Certificate for hostname '%s', in file (or by nickname):\n"
            "     %s\n\n",
            hostname, filename);

    if (renew) {
        fputs("  The certificate needs to be renewed; this can be done\n"
              "  using the 'genkey' program.\n\n"
              "  Browsers will not be able to correctly connect to this\n"
              "  web site using SSL until the certificate is renewed.\n",
              out);
    } else {
        char until[TIME_SIZE];
        char *result = pr_ctime(start, until, TIME_SIZE);
        assert(result == until);
        if (strlen(until) < sizeof(until)) until[strlen(until)] = '\0';
        fprintf(out,
                "  The certificate is not valid until %s.\n\n"
                "  Browsers will not be able to correctly connect to this\n"
                "  web site using SSL until the certificate becomes valid.\n",
                until);
    }

    fputs("\n"
          " ##########################################################\n"
          "                                  Generated by certwatch(1)\n\n",
          out);
    return 1;
}

/* Extract the common name of 'cert' into 'buf'. */
static int get_common_name(CERTCertificate *cert, char *buf, size_t bufsiz)
{
    /* FIXME --- truncating names with spaces */
    size_t namelen;
    char *name = CERT_GetCommonName(&cert->subject);

    if (!name) return -1;

    namelen = strlen(name);
    if (bufsiz < namelen+1) return -1;

    strncpy(buf, name, namelen);
    buf[namelen] = '\0';
    PORT_Free(name);

    return 0;
}

/* Check whether the certificate in filename 'name' has expired;
 * issue a warning message if 'quiet' is zero.  If quiet is non-zero,
 * returns one to indicate that a warning would have been issued, zero
 * to indicate no warning would be issued, or -1 if an error
 * occurred.
 *
 * When byNickname is 1 then 'name' is a nickname to search
 * for in the database otherwise it's the certificate file.
 */
static int check_cert(const char *name, int byNickname, int quiet)
{
    CERTCertificate *cert;
    SECCertTimeValidity validity;
    PRTime notBefore, notAfter;
    char cname[128];

    int doWarning = 0;

    /* parse the cert */
    cert = byNickname
        ? CERT_FindCertByNickname(CERT_GetDefaultCertDB(), (char *)name)
        : PEMUTIL_PEM_read_X509(name);
    if (cert == NULL) return -1;

    /* determine the validity period of the cert. */
    validity = CERT_CheckCertValidTimes(cert, PR_Now(), PR_FALSE);
    if (validity == secCertTimeUndetermined) goto cleanup;

    /* get times out of the cert */
    if (CERT_GetCertTimes(cert, &notBefore, &notAfter)
        != SECSuccess) goto cleanup;

    /* find the subject's commonName attribute */
    if (get_common_name(cert, cname, sizeof cname))
        goto cleanup;

    /* don't warn about the automatically generated certificate */
    if (strcmp(cname, "localhost") == 0 ||
        strcmp(cname, "localhost.localdomain") == 0)
        goto cleanup;

    doWarning = 1; /* ok so far, may do the warning */

cleanup:
    if (cert) CERT_DestroyCertificate(cert);
    if (!doWarning) return -1;

    return warning(stdout, name, cname, validity,
                   notBefore, notAfter, PR_Now(), quiet);
}

int main(int argc, char **argv)
{
    int optc, quiet = 0;
    const char *shortopts = "qp:a:d:w:c:k:";
    static const struct option longopts[] = {
        { "quiet", no_argument, NULL, 'q' },
        { "period", required_argument, NULL, 'p' },
        { "address", required_argument, NULL, 'a' },
        { "configdir", required_argument, NULL, 'd' },
        { "passwordfile", required_argument, NULL, 'w' },
        { "certdbprefix", required_argument, NULL, 'c' },
        { "keydbprexix", required_argument, NULL, 'k' },
        { NULL }
    };
    char *certDBPrefix = "";
    char *keyDBPrefix = "";
    char *configdir = NULL;    /* contains the cert database */
    char *passwordfile = NULL; /* module password file */
    int byNickname = 0;        /* whether to search by nickname */

    /* The 'timezone' global is needed to adjust local times from
     * mktime() back to UTC: */
    tzset();

    while ((optc = getopt_long(argc, argv, shortopts, longopts, NULL)) != -1) {
        switch (optc) {
        case 'q':
            quiet = 1;
            break;
        case 'p':
            warn_period = atoi(optarg);
            break;
        case 'a':
            warn_address = strdup(optarg);
            break;
        case 'd':
            configdir = strdup(optarg);
            byNickname = 1;
            break;
        case 'w':
            passwordfile = strdup(optarg);
            break;
        case 'c':
            certDBPrefix = strdup(optarg);
            break;
        case 'k':
            keyDBPrefix = strdup(optarg);
            break;
        default:
            exit(2);
            break;
        }
    }

    /* NSS initialization */

    if (byNickname) {
        /* cert in database */
        if (NSS_Initialize(configdir, certDBPrefix, keyDBPrefix,
                   SECMOD_DB, NSS_INIT_READONLY) != SECSuccess) {
            return EXIT_FAILURE;
        }
        /* in case module requires a password */
        if (passwordfile) {
            PK11_SetPasswordFunc(GetModulePassword);
        }
    } else {
        /* cert in a pem file */
        char *certDir = getenv("SSL_DIR"); /* Look in $SSL_DIR */
        if (!certDir) {
            certDir = "/etc/pki/nssdb";
        }
        if (NSS_Initialize(certDir, certDBPrefix, keyDBPrefix,
                   SECMOD_DB, NSS_INIT_READONLY) != SECSuccess) {
            printf("NSS_Init(\"%s\") failed\n", certDir);
            return EXIT_FAILURE;
        }
    }

    /* When byNickname is 1 argv[optind] is a nickname otherwise a filename. */
    return check_cert(argv[optind], byNickname, quiet) == 1
                      ? EXIT_SUCCESS : EXIT_FAILURE;
}
