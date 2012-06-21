Name:       aul
Summary:    App utility library
Version:	0.0.169
Release:    2
Group:      System/Libraries
License:    Apache License, Version 2.0
Source0:    %{name}-%{version}.tar.gz
Source101:  launchpad-preload.service
Source102:  ac.service
Source1001: packaging/aul.manifest 

Requires(post): /sbin/ldconfig
Requires(post): /usr/bin/systemctl
Requires(postun): /sbin/ldconfig
Requires(postun): /usr/bin/systemctl
Requires(preun): /usr/bin/systemctl

BuildRequires:  cmake
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(x11)
BuildRequires:  pkgconfig(app-checker)
BuildRequires:  pkgconfig(app-checker-server)
BuildRequires:  pkgconfig(ecore)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(ail)
BuildRequires:  pkgconfig(xdgmime)
BuildRequires:  pkgconfig(libprivilege-control)
BuildRequires:  pkgconfig(rua)


%description
Application utility library

%package devel
Summary:    App utility library (devel)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
Application utility library (devel)


%prep
%setup -q

%build
cp %{SOURCE1001} .
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}/etc/init.d
install -m 755 launchpad_run %{buildroot}/etc/init.d

mkdir -p %{buildroot}/etc/rc.d/rc3.d
mkdir -p %{buildroot}/etc/rc.d/rc4.d
ln -sf ../../init.d/launchpad_run %{buildroot}/%{_sysconfdir}/rc.d/rc3.d/S35launchpad_run
ln -sf ../../init.d/launchpad_run %{buildroot}/%{_sysconfdir}/rc.d/rc4.d/S80launchpad_run

mkdir -p %{buildroot}/opt/dbspace
sqlite3 %{buildroot}/opt/dbspace/.mida.db < %{buildroot}/opt/share/mida_db.sql
rm -rf %{buildroot}/opt/share/mida_db.sql

mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants
install -m 0644 %SOURCE101 %{buildroot}%{_libdir}/systemd/system/launchpad-preload.service
install -m 0644 %SOURCE102 %{buildroot}%{_libdir}/systemd/system/ac.service
ln -s ../launchpad-preload.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/launchpad-preload.service
ln -s ../ac.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/ac.service


%preun
if [ $1 == 0 ]; then
    systemctl stop launchpad-preload.service
    systemctl stop ac.service
fi

%post
/sbin/ldconfig
systemctl daemon-reload
if [ $1 == 1 ]; then
    systemctl restart launchpad-preload.service
    systemctl restart ac.service
fi

%postun -p /sbin/ldconfig
systemctl daemon-reload

%files
%manifest aul.manifest
%attr(0644,root,root) %{_libdir}/libaul.so.0
%attr(0644,root,root) %{_libdir}/libaul.so.0.1.0
%{_sysconfdir}/init.d/launchpad_run
%attr(0755,root,root) %{_bindir}/aul_service.sh
%attr(0755,root,root) %{_bindir}/aul_service_test.sh
%attr(0755,root,root) %{_sysconfdir}/rc.d/rc3.d/S35launchpad_run
%attr(0755,root,root) %{_sysconfdir}/rc.d/rc4.d/S80launchpad_run
%config(noreplace) %attr(0644,root,app) /opt/dbspace/.mida.db
%config(noreplace) %attr(0644,root,app) /opt/dbspace/.mida.db-journal
%{_bindir}/aul_mime.sh
%{_bindir}/aul_test
%{_bindir}/launch_app
/opt/share/miregex/*
/opt/share/service/*
/opt/share/preload_list.txt
%{_bindir}/launchpad_preloading_preinitializing_daemon
%{_bindir}/ac_daemon
%{_libdir}/systemd/system/multi-user.target.wants/launchpad-preload.service
%{_libdir}/systemd/system/multi-user.target.wants/ac.service
%{_libdir}/systemd/system/launchpad-preload.service
%{_libdir}/systemd/system/ac.service

%files devel
%manifest aul.manifest
/usr/include/aul/*.h
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc


