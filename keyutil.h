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

#ifndef _KEYUTIL_H
#define _KEYUTIL_H

#include "secutil.h"

extern char *progName;

enum certutilExtns {
    ext_keyUsage = 0,
    ext_basicConstraint,
    ext_authorityKeyID,
    ext_CRLDistPts,
    ext_NSCertType,
    ext_extKeyUsage,
    ext_authInfoAcc,
    ext_subjInfoAcc,
    ext_certPolicies,
    ext_policyMappings,
    ext_policyConstr,
    ext_inhibitAnyPolicy,
    ext_subjectKeyID,
    ext_End
};

typedef PRBool certutilExtnList[ext_End];

extern SECStatus
AddExtensions(void *extHandle, const char *emailAddrs, const char *dnsNames,
              certutilExtnList extList);

#endif  /* _KEYUTIL_H */

