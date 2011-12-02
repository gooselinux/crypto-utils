
%define crver 1.3

Summary: SSL certificate and key management utilities
Name: crypto-utils
Version: 2.4.1
Release: 24.2%{?dist}
Source: crypto-rand-%{crver}.tar.gz
Source1: genkey.pl
Source2: certwatch.c
Source3: certwatch.cron
Source4: certwatch.xml
Source5: genkey.xml
Source6: keyrand.c
Source7: COPYING
Source8: keyrand.xml
Source9: pemutil.c
Source10: keyutil.c
Source11: certext.c
Source12: secutil.c
Source13: secerror.c
Source14: keyutil.h
Source15: secutil.h
Source16: NSPRerrs.h
Source17: SECerrs.h
Source18: copying
Group: Applications/System
License: MIT and GPLv2+
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: nss-devel, pkgconfig, newt-devel, xmlto
BuildRequires: perl-devel, perl(Newt), perl(ExtUtils::MakeMaker)
Requires: perl(Newt), nss >= 3.12.2
Requires: %(eval `perl -V:version`; echo "perl(:MODULE_COMPAT_$version)")
Obsoletes: crypto-rand

%description
This package provides tools for managing and generating
SSL certificates and keys.

%prep
%setup -q -n crypto-rand-%{crver}

%build 
%configure --with-newt=%{_prefix} CFLAGS="$CFLAGS -fPIC"
make -C librand

cc $RPM_OPT_FLAGS -Wall -Werror -I/usr/include/nspr4 -I/usr/include/nss3 \
   $RPM_SOURCE_DIR/certwatch.c $RPM_SOURCE_DIR/pemutil.c \
   -o certwatch -lnspr4 -lnss3

cc $RPM_OPT_FLAGS -Wall -Werror -I/usr/include/nspr4 -I/usr/include/nss3 \
   $RPM_SOURCE_DIR/keyutil.c \
   $RPM_SOURCE_DIR/certext.c \
   $RPM_SOURCE_DIR/secutil.c \
   $RPM_SOURCE_DIR/secerror.c \
   -o keyutil -lnspr4 -lnss3

cc $RPM_OPT_FLAGS -Wall -Werror \
   $RPM_SOURCE_DIR/keyrand.c -o keyrand -lnewt

date +"%e %B %Y" | tr -d '\n' > date.xml
echo -n %{version} > version.xml

for m in certwatch.xml genkey.xml keyrand.xml; do
  cp $RPM_SOURCE_DIR/${m} .
  xmlto man ${m} 
done

pushd Makerand
perl -pi -e "s/Stronghold/Crypt/g" *
perl Makefile.PL PREFIX=$RPM_BUILD_ROOT/usr OPTIMIZE="$RPM_OPT_FLAGS" INSTALLDIRS=vendor
make
popd

%install
rm -rf $RPM_BUILD_ROOT

sed -n '1,/^ \*\/$/p' librand/qshs.c > LICENSE.librand
cp -p $RPM_SOURCE_DIR/COPYING .

pushd Makerand
make install
popd

find $RPM_BUILD_ROOT -name Makerand.so | xargs chmod 755

find $RPM_BUILD_ROOT \( -name perllocal.pod -o -name .packlist \) -exec rm -v {} \;
find $RPM_BUILD_ROOT -type f -name '*.bs' -a -size 0 -exec rm -f {} ';'
find $RPM_BUILD_ROOT -depth -type d -exec rmdir {} 2>/dev/null ';'

mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/cron.daily \
         $RPM_BUILD_ROOT%{_mandir}/man1 \
         $RPM_BUILD_ROOT%{_bindir}

# install keyrand
install -c -m 755 keyrand $RPM_BUILD_ROOT%{_bindir}/keyrand

# install certwatch
install -c -m 755 certwatch $RPM_BUILD_ROOT%{_bindir}/certwatch
install -c -m 755 $RPM_SOURCE_DIR/certwatch.cron \
   $RPM_BUILD_ROOT%{_sysconfdir}/cron.daily/certwatch
for f in certwatch genkey keyrand; do 
   install -c -m 644 ${f}.1 $RPM_BUILD_ROOT%{_mandir}/man1/${f}.1
done

# install keyutil
install -c -m 755 keyutil $RPM_BUILD_ROOT%{_bindir}/keyutil

# install genkey
sed -e "s|^\$bindir.*$|\$bindir = \"%{_bindir}\";|" \
    -e "s|^\$ssltop.*$|\$ssltop = \"/etc/pki/tls\";|" \
    -e "s|^\$sslconf.*$|\$sslconf = \"/etc/pki/tls/openssl.cnf\";|" \
    -e "s|^\$cadir.*$|\$cadir = \"/etc/pki/CA\";|" \
    -e "1s|.*|\#\!/usr/bin/perl|g" \
    -e "s/'Challenge',/'Email','Challenge',/g" \
    -e "/@EXTRA@/d" \
  < $RPM_SOURCE_DIR/genkey.pl > $RPM_BUILD_ROOT%{_bindir}/genkey

chmod -R u+w $RPM_BUILD_ROOT

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%attr(0755,root,root) %{_bindir}/*
%attr(0755,root,root) %{_sysconfdir}/cron.daily/certwatch
%{_mandir}/man*/*
%doc LICENSE* COPYING
%{perl_vendorarch}/Crypt
%{perl_vendorarch}/auto/Crypt

%changelog
* Thu Jun 24 2010 Joe Orton <jorton@redhat.com> - 2.4.1-24.2
- added dist to Release (#604535)

* Fri Dec 11 2009 Dennis Gregorovic <dgregor@redhat.com> - 2.4.1-24.1
- Rebuilt for RHEL 6

* Sun Oct 04 2009 Elio Maldonado<emaldona@redhat.com> - 2.4.1-24
- Retagging for a Fedora-12 build (#526720)

* Thu Oct 01 2009 Elio Maldonado<emaldona@redhat.com> - 2.4.1-23
- Fix genkey to produce CSRs, certs, and key in ascii PEM format (#526720)

* Fri Jul 24 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.4.1-22
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Thu May 21 2009 Elio Maldonado <emaldona@redhat.com> - 2.4.1-20
- certwatch: Fixed cert suffix to be .crt as Apache expects it (#162116)

* Sun Mar 15 2009 Elio Maldonado <emaldona@redhat.com> - 2.4.1-18
- certwatch: Fixed cert expiry time calculations (#473860)
- keyutil: Fixed segfault on certificate generation and missing of key/cert pem files (#479886)

* Tue Feb 24 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.4.1-17
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Fri Feb 20 2009 Elio Maldonado <emaldona@redhat.com> - 2.4.1-14
- keyutil: Fixed bug where key pem file was not written (#473860)
- keyutil: Fixed reverse logic that prevented output of the pem encoded key

* Thu Jan 29 2009 Elio Maldonado <emaldona@redhat.com> - 2.4.1-9
- certwatch: Fixed cert expiry time calculations (#473860)
- keyutil: Fixed segfault on certificate generation (#479886)
- genkey: Fixed key file name extension

* Wed Jan 21 2009 Elio Maldonado <emaldona@redhat.com> - 2.4.1-8
- certwatch: Fixed cert expiry time warnings off by one error (#473860)

* Wed Jan 21 2009 Elio Maldonado <emaldona@redhat.com> - 2.4.1-7
- certwatch: Fixed cert expiry time warnings (#473860)

* Mon Jan 05 2009 Elio Maldonado <emaldona@redhat.com> - 2.4.1-6
- genkey: fix ca key name extension

* Wed Dec 28 2008 Elio Maldonado <emaldona@redhat.com> - 2.4.1-5
- genkey: fix server key name extension
- certwatch: code cleanup

* Wed Dec 24 2008 Elio Maldonado <emaldona@redhat.com> - 2.4.1-4
- Fix certwatch time calculations for expiring certificates (#473860)

* Mon Nov 03 2008 Elio Maldonado <emaldona@redhat.com> - 2.4.1-3
- preauthenticate to modules using specially formatted password file

* Sun Oct 26 2008 Elio Maldonado <emaldona@redhat.com> - 2.4.1-2
- enabled renewal for certs in the nss database
- disabled renewal for certs in pem files
- added man page examples
- requires nss 3.12.2 or higher

* Tue Jun 03 2008 Elio Maldonado <emaldona@redhat.com> - 2.4-2
- removed unneeded declaration in pemutil

* Tue Jun 03 2008 Elio Maldonado <emaldona@redhat.com> - 2.4-1
- crypto-utils ported to use NSS for cryptography (#346731)
- updated documentation accordingly

* Mon Mar  3 2008 Tom "spot" Callaway <tcallawa@redhat.com> - 2.3-10
- rebuild for new perl again

* Tue Feb 19 2008 Fedora Release Engineering <rel-eng@fedoraproject.org> - 2.3-9
- Autorebuild for GCC 4.3

* Thu Feb  7 2008 Tom "spot" Callaway <tcallawa@redhat.com> 2.3-8
- rebuild for new perl

* Wed Dec  5 2007 Joe Orton <jorton@redhat.com> 2.3-7
- rebuild for new OpenSSL

* Tue Oct 30 2007 Joe Orton <jorton@redhat.com> 2.3-6
- genkey: wording fix

* Wed Oct 24 2007 Joe Orton <jorton@redhat.com> 2.3-5
- genkey: skip the CA selection dialog; the CA-specific 
  instructions are all out-of-date
- man page updates, add man page for keyrand

* Thu Aug 23 2007 Joe Orton <jorton@redhat.com> 2.3-4
- fix certwatch -p too
- clarify License; package license texts

* Wed Aug 22 2007 Joe Orton <jorton@redhat.com> 2.3-3
- fix certwatch -a (Tuomo Soini, #253819)

* Thu Mar  1 2007 Joe Orton <jorton@redhat.com> 2.3-2
- various cleanups; require perl(Newt) throughout not newt-perl

* Thu Aug 17 2006 Joe Orton <jorton@redhat.com> 2.3-1
- add GPL-licensed keyrand replacement (#20254)

* Wed Jul 12 2006 Jesse Keating <jkeating@redhat.com> - 2.2-9.2.2
- rebuild

* Fri Feb 10 2006 Jesse Keating <jkeating@redhat.com> - 2.2-9.2.1
- bump again for double-long bug on ppc(64)

* Tue Feb 07 2006 Jesse Keating <jkeating@redhat.com> - 2.2-9.2
- rebuilt for new gcc4.1 snapshot and glibc changes

* Fri Dec 09 2005 Jesse Keating <jkeating@redhat.com>
- rebuilt

* Thu Nov 24 2005 Joe Orton <jorton@redhat.com> 2.2-9
- rebuild for new slang

* Tue Nov  8 2005 Tomas Mraz <tmraz@redhat.com> - 2.2-8
- rebuilt with new openssl

* Mon Oct  3 2005 Petr Rockai <prockai@redhat.com> - 2.2-7
- rebuild against newt 0.52

* Thu May 26 2005 Joe Orton <jorton@redhat.com> 2.2-6
- certwatch: use UTC time correctly (Tomas Mraz, #158703)

* Fri May 13 2005 Joe Orton <jorton@redhat.com> 2.2-5
- genkey(1): fix paths to use /etc/pki

* Wed Apr 27 2005 Joe Orton <jorton@redhat.com> 2.2-4
- genkey: create private key files with permissions 0400
- genkey: tidy up error handling a little

* Tue Apr 26 2005 Joe Orton <jorton@redhat.com> 2.2-3
- pass $OPTIONS to $HTTPD in certwatch.cron
- man page tweaks

* Tue Apr 26 2005 Joe Orton <jorton@redhat.com> 2.2-2
- add configuration options for certwatch (#152990)
- allow passing options in certwatch.cron via $CERTWATCH_OPTS
- require openssl with /etc/pki/tls

* Mon Apr 25 2005 Joe Orton <jorton@redhat.com> 2.2-1
- adapt to use /etc/pki

* Fri Mar  4 2005 Joe Orton <jorton@redhat.com> 2.1-6
- rebuild

* Tue Feb 15 2005 Joe Orton <jorton@redhat.com> 2.1-5
- certwatch: prevent warnings for duplicate certs (#103807)
- make /etc/cron.daily/certwatch 0755 (#141003)
- add genkey(1) man page (#134821)

* Tue Oct 19 2004 Joe Orton <jorton@redhat.com> 2.1-4
- make certwatch(1) warning distro-neutral
- update to crypto-rand 1.1, fixing #136093

* Wed Oct 13 2004 Joe Orton <jorton@redhat.com> 2.1-3
- send warnings To: root rather than root@localhost (#135533)

* Wed Oct  6 2004 Joe Orton <jorton@redhat.com> 2.1-2
- add BuildRequire newt-devel, xmlto (#134695)

* Fri Sep 10 2004 Joe Orton <jorton@redhat.com> 2.1-1
- add /usr/bin/certwatch
- support --days argument to genkey (#131045)

* Tue Aug 17 2004 Joe Orton <jorton@redhat.com> 2.0-6
- add perl MODULE_COMPAT requirement

* Mon Aug 16 2004 Joe Orton <jorton@redhat.com> 2.0-5
- rebuild

* Mon Sep 15 2003 Joe Orton <jorton@redhat.com> 2.0-4
- hide private key passwords during entry
- fix CSR generation

* Mon Sep  1 2003 Joe Orton <jorton@redhat.com> 2.0-3
- fix warnings when in UTF-8 locale

* Tue Aug 26 2003 Joe Orton <jorton@redhat.com> 2.0-2
- allow upgrade from Stronghold 4.0

* Mon Aug  4 2003 Joe Orton <jorton@redhat.com> 2.0-1
- update for RHEL

* Wed Sep 11 2002 Joe Orton <jorton@redhat.com> 1.0-12
- rebuild

* Thu Aug 22 2002 Joe Orton <jorton@redhat.com> 1.0-11
- fix location of OpenSSL configuration file in gencert

* Mon Jul 15 2002 Joe Orton <jorton@redhat.com> 1.0-10
- fix getca SERVERROOT, SSLTOP expansion (#68870)

* Mon May 13 2002 Joe Orton <jorton@redhat.com> 1.0-9
- improvements to genkey

* Mon May 13 2002 Joe Orton <jorton@redhat.com> 1.0-8
- add php.ini handling to stronghold-config 

* Mon May 13 2002 Joe Orton <jorton@redhat.com> 1.0-7
- restore stronghold-config

* Tue May 07 2002 Gary Benson <gbenson@redhat.com> 1.0-6
- remove stronghold-config

* Tue Apr 09 2002 Gary Benson <gbenson@redhat.com> 1.0-5
- change the group to match crypto-rand
- change Copyright to License

* Mon Mar 25 2002 Gary Benson <gbenson@redhat.com> 1.0-4
- hack to clean up some cruft that gets left in the docroot after we
  install.

* Fri Mar 22 2002 Gary Benson <gbenson@redhat.com>
- excise interchange.

* Wed Feb 13 2002 Gary Benson <gbenson@redhat.com> 1.0-3
- ask about interchange too.
- make /etc/sysconfig/httpd nicer.

* Thu May 17 2001 Joe Orton <jorton@redhat.com>
- Redone for Red Hat Linux.

* Mon Mar 20 2001 Mark Cox <mjc@redhat.com>
- Changes to make genkey a perl script

* Mon Dec 04 2000 Joe Orton <jorton@redhat.com>
- Put the stronghold/bin -> stronghold/ssl/bin symlink in the %files section
  rather than creating it in %post.

* Fri Nov 24 2000 Mark Cox <mjc@redhat.com>
- No need for .configure scripts, do the substitution ourselves

* Tue Nov 21 2000 Mark Cox <mjc@redhat.com>
- First version. Because this depends on a build environment
- We won't worry about ni-scripts for now, they're not used anyhow

