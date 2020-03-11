%global systemctl_bin /usr/bin/systemctl

Name:           openldap
Version:        2.4.46
Release:        15
Summary:        LDAP support libraries
License:        OpenLDAP
URL:            https://www.openldap.org/
Source0:        https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-%{version}.tgz
Source1:        slapd.service
Source2:        slapd.tmpfiles
Source3:        slapd.ldif
Source4:        ldap.conf
Source10:       ltb-project-openldap-ppolicy-check-password-1.1.tar.gz
Source50:       libexec-functions
Source52:       libexec-check-config.sh
Source53:       libexec-upgrade-db.sh

Patch0:         openldap-manpages.patch
Patch2:         openldap-reentrant-gethostby.patch
Patch3:         openldap-smbk5pwd-overlay.patch
Patch5:         openldap-ai-addrconfig.patch
Patch17:        openldap-allop-overlay.patch

# http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=327585
Patch19:        openldap-switch-to-lt_dlopenadvise-to-get-RTLD_GLOBAL-set.patch
Patch20:        openldap-ldapi-sasl.patch
Patch21:        openldap-openssl-allow-ssl3.patch
Patch90:        check-password-makefile.patch
Patch91:        check-password.patch
Patch6000:      bugfix-openldap-autoconf-pkgconfig-nss.patch
Patch6001:      bugfix-openldap-nss-ciphers-use-nss-defaults.patch
Patch6002:      bugfix-openldap-nss-ignore-certdb-type-prefix.patch
Patch6003:      bugfix-openldap-nss-pk11-freeslot.patch
Patch6004:      bugfix-openldap-nss-protocol-version-new-api.patch
Patch6005:      bugfix-openldap-nss-unregister-on-unload.patch
Patch6006:      bugfix-openldap-nss-update-list-of-ciphers.patch
Patch6007:      bugfix-openldap-nss-ciphersuite-handle-masks-correctly.patch
Patch6008:      bugfix-openldap-ssl-deadlock-revert.patch
Patch6009:      bugfix-openldap-support-tlsv1-and-later.patch
Patch6010:      bugfix-openldap-temporary-ssl-thr-init-race.patch
Patch6011:      Fix-calls-to-SLAP_DEVPOLL_SOCK_LX-for-multi-listener.patch
Patch6012:      Fixup-for-binary-config-attrs.patch
Patch6013:      ITS-8864-Fix-ber_realloc-after-a-partial-ber_flush.patch

Patch6014:      ITS-8840-Fix-domainScope-control-to-ensure-the-contr.patch
Patch6015:      ITS-8843-check-for-NULL-modlist.patch
Patch6016:      Fix-quoting-example.patch
Patch6017:      ITS-8667-Do-not-finish-glue-initialisation-in-tool-m.patch
Patch6018:      ITS-8842-Do-some-printability-checks-on-the-dc-RDN.patch
Patch6019:      ITS-8909-fix-authz-policy-all-condition.patch
Patch6020:      ITS-8909-additional-tweak.patch
Patch6021:      Fix-index-delete.patch
Patch6022:      ITS-8756-remove-loose-pg-from-dirty-list-in-freelist.patch
Patch6023:      ITS-8918-fix-typo.patch
Patch6024:      ITS-8923-fix-dyngroup-NO_SUCH_OBJECT-error-handling.patch
Patch6025:      ITS-8878-Include-the-first-character-in-the-transfor.patch
Patch6026:      ITS-8752-maybe-related.patch
Patch6027:      ITS-8932-check-rdnNormalize-success.patch
Patch6028:      ITS-8727-plug-ber-leaks.patch
Patch6029:      ITS-8948-Fix-BDB-lib-to-only-be-linked-with-static-b.patch
Patch6030:      ITS-8663-Fix-memberof-SLAP_CONFIG_EMIT.patch
Patch6031:      ITS-8472-only-do-index-cleanup-if-DB-is-running.patch
Patch6032:      ITS-8957-Fix-ASYNC-TLS.patch
Patch6033:      ITS-8980-fix-async-connections-with-non-blocking-TLS.patch
Patch6034:      CVE-2019-13057-1.patch
Patch6035:      CVE-2019-13057-2.patch
Patch6036:      CVE-2019-13057-3.patch
Patch6037:      CVE-2019-13057-4.patch
Patch6038:      CVE-2019-13565.patch
Patch6039:      0001-openldap-bugfix-make-test.patch

BuildRequires:  cyrus-sasl-devel openssl-devel krb5-devel unixODBC-devel
BuildRequires:  glibc-devel libtool libtool-ltdl-devel groff perl-interpreter perl-devel perl-generators perl-ExtUtils-Embed

%description
OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
Protocol) applications and development tools. LDAP is a set of
protocols for accessing directory services (usually phone book style
information, but other information is possible) over the Internet,
similar to the way DNS (Domain Name System) information is propagated
over the Internet. The openldap package contains configuration files,
libraries, and documentation for OpenLDAP.

%package        devel
Summary:        LDAP development libraries and header files
Requires:       openldap = %{version}-%{release} cyrus-sasl-devel

%description    devel
The openldap-devel package includes the development libraries and
header files needed for compiling applications that use LDAP
(Lightweight Directory Access Protocol) internals. LDAP is a set of
protocols for enabling directory services over the Internet. Install
this package only if you plan to develop or will need to compile
customized LDAP clients.

%package        servers
Summary:        LDAP server
License:        OpenLDAP
Requires:       openldap = %{version}-%{release} libdb-utils
Requires(pre):  shadow-utils
%{?systemd_requires}
BuildRequires:  systemd
BuildRequires:  libdb-devel cracklib-devel
Provides:       ldif2ldbm

%description servers
OpenLDAP is an open-source suite of LDAP (Lightweight Directory Access
Protocol) applications and development tools. LDAP is a set of
protocols for accessing directory services (usually phone book style
information, but other information is possible) over the Internet,
similar to the way DNS (Domain Name System) information is propagated
over the Internet. This package contains the slapd server and related files.

%package        clients
Summary:        LDAP client utilities
Requires:       openldap = %{version}-%{release}

%description clients
OpenLDAP is an open-source suite of LDAP (Lightweight Directory Access
Protocol) applications and development tools. LDAP is a set of
protocols for accessing directory services (usually phone book style
information, but other information is possible) over the Internet,
similar to the way DNS (Domain Name System) information is propagated
over the Internet. The openldap-clients package contains the client
programs needed for accessing and modifying OpenLDAP directories.

%package_help

%prep
%setup -q -c -a 0 -a 10

pushd openldap-%{version}

AUTOMAKE=%{_bindir}/true autoreconf -fi

%patch0 -p1
%patch2 -p1
%patch3 -p1
%patch5 -p1
%patch17 -p1
%patch19 -p1
%patch20 -p1
%patch21 -p1

%patch6000 -p1
%patch6001 -p1
%patch6002 -p1
%patch6003 -p1
%patch6004 -p1
%patch6005 -p1
%patch6006 -p1
%patch6007 -p1
%patch6008 -p1
%patch6009 -p1
%patch6010 -p1
%patch6011 -p1
%patch6012 -p1
%patch6013 -p1
%patch6014 -p1
%patch6015 -p1
%patch6016 -p1
%patch6017 -p1
%patch6018 -p1
%patch6019 -p1
%patch6020 -p1
%patch6021 -p1
%patch6022 -p1
%patch6023 -p1
%patch6024 -p1
%patch6025 -p1
%patch6026 -p1
%patch6027 -p1
%patch6028 -p1
%patch6029 -p1
%patch6030 -p1
%patch6031 -p1
%patch6032 -p1
%patch6033 -p1
%patch6034 -p1
%patch6035 -p1
%patch6036 -p1
%patch6037 -p1
%patch6038 -p1
%patch6039 -p1

ln -s ../../../contrib/slapd-modules/smbk5pwd/smbk5pwd.c servers/slapd/overlays
mv contrib/slapd-modules/smbk5pwd/README contrib/slapd-modules/smbk5pwd/README.smbk5pwd
ln -s ../../../contrib/slapd-modules/allop/allop.c servers/slapd/overlays
mv contrib/slapd-modules/allop/README contrib/slapd-modules/allop/README.allop
mv contrib/slapd-modules/allop/slapo-allop.5 doc/man/man5/slapo-allop.5

mv servers/slapd/back-perl/README{,.back_perl}

for filename in doc/drafts/draft-ietf-ldapext-acl-model-xx.txt; do
        iconv -f iso-8859-1 -t utf-8 "$filename" > "$filename.utf8"
        mv "$filename.utf8" "$filename"
done

popd

pushd ltb-project-openldap-ppolicy-check-password-1.1
%patch90 -p1
%patch91 -p1
popd

%build

%set_build_flags
export CFLAGS="${CFLAGS} ${LDFLAGS} -Wl,--as-needed -DLDAP_CONNECTIONLESS -DLDAP_USE_NON_BLOCKING_TLS"

pushd openldap-%{version}
%configure \
        --enable-debug --enable-dynamic --enable-dynacl \
        --enable-cleartext --enable-crypt --enable-lmpasswd \
        --enable-spasswd --enable-modules --enable-rewrite \
        --enable-rlookups --enable-slapi --disable-slp \
        --enable-backends=mod --enable-bdb=yes --enable-hdb=yes \
        --enable-mdb=yes --enable-monitor=yes --disable-ndb \
        --disable-sql --enable-overlays=mod --disable-static \
        --with-cyrus-sasl --without-fetch --with-threads \
        --with-pic --with-gnu-ld --libexecdir=%{_libdir}

%make_build
popd

pushd ltb-project-openldap-ppolicy-check-password-1.1
make LDAP_INC="-I../openldap-%{version}/include \
 -I../openldap-%{version}/servers/slapd \
 -I../openldap-%{version}/build-servers/include"
popd

%install
install -d  %{buildroot}%{_libdir}/

pushd openldap-%{version}
%make_install STRIP=""
popd

pushd ltb-project-openldap-ppolicy-check-password-1.1
mv check_password.so check_password.so.1.1
ln -s check_password.so.1.1 %{buildroot}%{_libdir}/openldap/check_password.so
install -m 755 check_password.so.1.1 %{buildroot}%{_libdir}/openldap/
install -d -m 755 %{buildroot}%{_sysconfdir}/openldap
cat > %{buildroot}%{_sysconfdir}/openldap/check_password.conf <<EOF
# OpenLDAP pwdChecker library configuration

#useCracklib 1
#minPoints 3
#minUpper 0
#minLower 0
#minDigit 0
#minPunct 0
EOF
mv README{,.check_pwd}
popd

install -d %{buildroot}%{_sysconfdir}/openldap/certs
install -d %{buildroot}%{_sharedstatedir}
install -d %{buildroot}%{_localstatedir}
install -m 0700 -d %{buildroot}%{_sharedstatedir}/ldap
install -m 0755 -d %{buildroot}%{_localstatedir}/run/openldap

install -d %{buildroot}%{_tmpfilesdir}
install -m 0644 %SOURCE2 %{buildroot}%{_tmpfilesdir}/slapd.conf

install -m 0644 %SOURCE4 %{buildroot}%{_sysconfdir}/openldap/ldap.conf

install -d %{buildroot}%{_libexecdir}
install -m 0755 -d %{buildroot}%{_libexecdir}/openldap
install -m 0644 %SOURCE50 %{buildroot}%{_libexecdir}/openldap/functions
install -m 0755 %SOURCE52 %{buildroot}%{_libexecdir}/openldap/check-config.sh
install -m 0755 %SOURCE53 %{buildroot}%{_libexecdir}/openldap/upgrade-db.sh

perl -pi -e "s|%{buildroot}||g" %{buildroot}%{_sysconfdir}/openldap/*.conf
perl -pi -e "s|%{buildroot}||g" %{buildroot}%{_mandir}/*/*.*
rm -f %{buildroot}%{_sysconfdir}/openldap/*.default
rm -f %{buildroot}%{_sysconfdir}/openldap/schema/*.default
rm -f %{buildroot}%{_sysconfdir}/openldap/slapd.conf
rm -f %{buildroot}%{_sysconfdir}/openldap/slapd.ldif

install -d %{buildroot}%{_unitdir}
install -m 0644 %SOURCE1 %{buildroot}%{_unitdir}/slapd.service

mv %{buildroot}%{_libdir}/slapd %{buildroot}%{_sbindir}/

for X in acl add auth cat dn index passwd test schema; do
        rm -f %{buildroot}%{_sbindir}/slap$X
        rm -f %{buildroot}%{_libdir}/slap$X
done

for X in acl add auth cat dn index passwd test schema; do
        ln -s slapd %{buildroot}%{_sbindir}/slap$X
done

pushd %{buildroot}%{_libdir}
v=%{version}
version=$(echo ${v%.[0-9]*})
for lib in liblber libldap libldap_r libslapi; do
        rm -f ${lib}.so
        ln -s ${lib}-${version}.so.2 ${lib}.so
done
popd

chmod 0755 %{buildroot}%{_libdir}/lib*.so*
chmod 0644 %{buildroot}%{_libdir}/lib*.*a

install -d %{buildroot}%{_datadir}
install -m 0755 -d %{buildroot}%{_datadir}/openldap-servers
install -m 0644 %SOURCE3 %{buildroot}%{_datadir}/openldap-servers/slapd.ldif
install -m 0700 -d %{buildroot}%{_sysconfdir}/openldap/slapd.d
mv %{buildroot}%{_sysconfdir}/openldap/schema/README README.schema
mv %{buildroot}%{_sysconfdir}/openldap/DB_CONFIG.example %{buildroot}%{_datadir}/openldap-servers/DB_CONFIG.example
chmod 0644 %{buildroot}%{_datadir}/openldap-servers/DB_CONFIG.example

%delete_la

rm -f %{buildroot}%{_localstatedir}/openldap-data/DB_CONFIG.example
rmdir %{buildroot}%{_localstatedir}/openldap-data

%ldconfig_scriptlets

%pre servers

getent group ldap &>/dev/null || groupadd -r -g 55 ldap
getent passwd ldap &>/dev/null || \
        useradd -r -g ldap -u 55 -d %{_sharedstatedir}/ldap -s /sbin/nologin -c "OpenLDAP server" ldap

if [ $1 -eq 2 ]; then

        old_version=$(rpm -q --qf=%%{version} openldap-servers)
        new_version=%{version}

        if [ "$old_version" != "$new_version" ]; then
                touch %{_sharedstatedir}/ldap/rpm_upgrade_openldap &>/dev/null
        fi
fi

exit 0


%post servers
%systemd_post slapd.service

if [[ ! -f %{_sysconfdir}/openldap/slapd.d/cn=config.ldif && \
      ! -f %{_sysconfdir}/openldap/slapd.conf
   ]]; then
      install -d  %{_sysconfdir}/openldap/slapd.d/ &>/dev/null || :
      /usr/sbin/slapadd -F %{_sysconfdir}/openldap/slapd.d/ -n0 -l %{_datadir}/openldap-servers/slapd.ldif
      chown -R ldap:ldap %{_sysconfdir}/openldap/slapd.d/
      %{systemctl_bin} try-restart slapd.service &>/dev/null
fi

start_slapd=0

if [ -f %{_sharedstatedir}/ldap/rpm_upgrade_openldap ]; then
        if %{systemctl_bin} --quiet is-active slapd.service; then
                %{systemctl_bin} stop slapd.service
                start_slapd=1
        fi

        %{_libexecdir}/openldap/upgrade-db.sh &>/dev/null
        rm -f %{_sharedstatedir}/ldap/rpm_upgrade_openldap
fi

if [ $1 -ge 1 ]; then
        if [ $start_slapd -eq 1 ]; then
                %{systemctl_bin} start slapd.service &>/dev/null || :
        else
                %{systemctl_bin} condrestart slapd.service &>/dev/null || :
        fi
fi

exit 0

%preun servers
%systemd_preun slapd.service

%postun servers
%systemd_postun_with_restart slapd.service

%triggerin servers -- libdb

if [ $2 -eq 2 ]; then
        if [ "$(rpm -q --qf="%%{version}\n" libdb | sed 's/\.[0-9]*$//' | sort -u | wc -l)" != "1" ]; then
                touch %{_sharedstatedir}/ldap/rpm_upgrade_libdb
        else
                rm -f %{_sharedstatedir}/ldap/rpm_upgrade_libdb
        fi
fi

exit 0


%triggerun servers -- libdb

if [ -f %{_sharedstatedir}/ldap/rpm_upgrade_libdb ]; then
        if %{systemctl_bin} --quiet is-active slapd.service; then
                %{systemctl_bin} stop slapd.service
                start=1
        else
                start=0
        fi

        %{_libexecdir}/openldap/upgrade-db.sh &>/dev/null
        rm -f %{_sharedstatedir}/ldap/rpm_upgrade_libdb

        [ $start -eq 1 ] && %{systemctl_bin} start slapd.service &>/dev/null
fi

exit 0

%check
pushd openldap-%{version}
make check
popd

%files
%defattr(-,root,root)
%license openldap-%{version}/COPYRIGHT
%license openldap-%{version}/LICENSE
%dir %{_sysconfdir}/openldap/certs
%config(noreplace) %{_sysconfdir}/openldap/ldap.conf
%dir %{_libexecdir}/openldap/
%{_libdir}/lib*.so.*

%files servers
%defattr(-,root,root)
%config(noreplace) %dir %attr(0750,ldap,ldap) %{_sysconfdir}/openldap/slapd.d
%config(noreplace) %{_sysconfdir}/openldap/schema
%config(noreplace) %{_sysconfdir}/openldap/check_password.conf
%{_tmpfilesdir}/slapd.conf
%dir %attr(0700,ldap,ldap) %{_sharedstatedir}/ldap
%dir %attr(-,ldap,ldap) %{_localstatedir}/run/openldap
%{_unitdir}/slapd.service
%{_datadir}/openldap-servers/
%{_libdir}/openldap/*
%{_libexecdir}/openldap/functions
%{_libexecdir}/openldap/check-config.sh
%{_libexecdir}/openldap/upgrade-db.sh
%{_sbindir}/sl*
%ghost %config(noreplace,missingok) %attr(0640,ldap,ldap) %{_sysconfdir}/openldap/slapd.conf

%files clients
%defattr(-,root,root)
%{_bindir}/*

%files devel
%defattr(-,root,root)
%{_libdir}/lib*.so
%{_includedir}/*

%files help
%defattr(-,root,root)
%{_mandir}/man*/*
%doc openldap-%{version}/ANNOUNCEMENT
%doc openldap-%{version}/CHANGES
%doc openldap-%{version}/README
%doc openldap-%{version}/doc/guide/admin/*.html
%doc openldap-%{version}/doc/guide/admin/*.png
%doc openldap-%{version}/servers/slapd/back-perl/SampleLDAP.pm
%doc openldap-%{version}/servers/slapd/back-perl/README.back_perl
%doc README.schema
%doc openldap-%{version}/doc/drafts openldap-%{version}/doc/rfc
%doc ltb-project-openldap-ppolicy-check-password-1.1/README.check_pwd

%changelog
* Wed Mar 11 2020 songnannan <songnannan2@huawei.com> - 2.4.46-15
- bugfix about conf file

* Fri Feb 21 2020 songnannan<songnannan2@huawei.com> - 2.4.46-14
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:bugfix about make check

* Sat Jan 11 2020 zhangrui<zhangrui182@huawei.com> - 2.4.46-13
- Type:cves
- ID:CVE-2017-17740
- SUG:NA
- DESC: fix CVE-2017-17740

* Mon Dec 30 2019 openEuler Buildteam <buildteam@openeuler.org> - 2.4.46-12
- Type:bugfix
- ID:
- SUG:
- DESC:modify the spec

* Sat Dec 21 2019 openEuler Buildteam <buildteam@openeuler.org> - 2.4.46-11
- Type:cves
- ID:CVE-2019-13565
- SUG:restart
- DESC:fix CVE--2019-13565

* Wed Sep 25 2019 openEuler Buildteam <buildteam@openeuler.org> - 2.4.46-10
- Type:cves
- ID:CVE-2019-13057
- SUG:NA
- DESC:fix CVE-2019-13057

* Tue Sep 17 2019 openEuler Buildteam <buildteam@openeuler.org> - 2.4.46-9
- Package init
