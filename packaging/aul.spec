%bcond_without privacy-manager-client
%bcond_with multi_user

Name:       aul
Summary:    App utility library
Version:    0.0.266
Release:    1
Group:      System/Libraries
License:    Apache License, Version 2.0
Source0:    %{name}-%{version}.tar.gz
Source101:  launchpad-preload@.service
Source102:  ac.service
Source103:  launchpad-preload_user.service
Source104:  ac_user.service
Source105:  ac.socket
Source106:  launchpad-preload.socket
Source1001: %{name}.manifest
Requires(post): /sbin/ldconfig
Requires(post): /usr/bin/systemctl
Requires(postun): /sbin/ldconfig
Requires(postun): /usr/bin/systemctl
Requires(preun): /usr/bin/systemctl

BuildRequires:  cmake
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(x11)
BuildRequires:  pkgconfig(ecore)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(ail)
BuildRequires:  xdgmime-devel, pkgconfig(xdgmime)
BuildRequires:  pkgconfig(libprivilege-control)
BuildRequires:  pkgconfig(app-checker)
BuildRequires:  pkgconfig(app-checker-server)
BuildRequires:  pkgconfig(rua)
BuildRequires:  pkgconfig(ecore-x)
BuildRequires:  pkgconfig(ecore-input)
BuildRequires:  pkgconfig(utilX)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(libsmack)
BuildRequires:	pkgconfig(app2sd)
%if %{with privacy-manager-client}
BuildRequires:  pkgconfig(privacy-manager-client)
%endif
BuildRequires:  pkgconfig(libsystemd-daemon)

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
cp %{SOURCE1001} .

%build
%cmake . \
%if %{with privacy-manger-client}
	-DENABLE_PRIVACY_MANAGER=On \
%else
	-DENABLE_PRIVACY_MANAGER=Off \
%endif
%if %{with multi_user}
	-DMULTI_USER_SUPPORT=On
%else
	-DMULTI_USER_SUPPORT=Off
%endif

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}/etc/init.d
install -m 755 launchpad_run %{buildroot}/etc/init.d

mkdir -p %{buildroot}/etc/rc.d/rc3.d
mkdir -p %{buildroot}/etc/rc.d/rc4.d
ln -sf ../../init.d/launchpad_run %{buildroot}/%{_sysconfdir}/rc.d/rc3.d/S34launchpad_run
ln -sf ../../init.d/launchpad_run %{buildroot}/%{_sysconfdir}/rc.d/rc4.d/S80launchpad_run

mkdir -p %{buildroot}/opt/dbspace
sqlite3 %{buildroot}/opt/dbspace/.mida.db < %{buildroot}/usr/share/aul/mida_db.sql
rm -rf %{buildroot}/usr/share/aul/mida_db.sql

%if %{with multi_user}
mkdir -p %{buildroot}/%{_unitdir_user}/
mkdir -p %{buildroot}/%{_unitdir_user}/sockets.target.wants
install -m 0644 %SOURCE103 %{buildroot}/%{_unitdir_user}/launchpad-preload.service
install -m 0644 %SOURCE106 %{buildroot}/%{_unitdir_user}/launchpad-preload.socket
ln -s ../launchpad-preload.socket %{buildroot}/%{_unitdir_user}/sockets.target.wants/launchpad-preload.socket
install -m 0644 %SOURCE104 %{buildroot}/%{_unitdir_user}/ac.service
install -m 0644 %SOURCE105 %{buildroot}/%{_unitdir_user}/ac.socket
ln -s ../ac.socket %{buildroot}/%{_unitdir_user}/sockets.target.wants/ac.socket
%else
mkdir -p %{buildroot}/%{_unitdir}/graphical.target.wants
install -m 0644 %SOURCE101 %{buildroot}/%{_unitdir}/launchpad-preload@.service
ln -s ../launchpad-preload@.service %{buildroot}/%{_unitdir}/graphical.target.wants/launchpad-preload@app.service
install -m 0644 %SOURCE102 %{buildroot}/%{_unitdir}/ac.service
ln -s ../ac.service %{buildroot}/%{_unitdir}/graphical.target.wants/ac.service
install -m 0644 %SOURCE105 %{buildroot}/%{_unitdir}/ac.socket
%endif

%preun
%if !%{with multi_user}
	%systemd_preun launchpad-preload@app.service ac.socket
%endif

%post
/sbin/ldconfig
systemctl daemon-reload
%if %{with multi_user}
#	systemctl --user enable ac.socket
#	systemctl --user start ac.socket
#	systemctl --user enable launchpad-preload.socket
#	systemctl --user start launchpad-preload.socket
%else
	systemctl restart launchpad-preload@app.service
	systemctl restart ac.service
%endif

%postun
/sbin/ldconfig
%if %{with multi_user}
#	systemctl --user daemon-reload
%else
	%systemd_postun launchpad-preload@app.service ac.socket
%endif

%files
%manifest %{name}.manifest
%attr(0644,root,root) %{_libdir}/libaul.so.0
%attr(0644,root,root) %{_libdir}/libaul.so.0.1.0
%{_sysconfdir}/init.d/launchpad_run
%attr(0755,root,root) %{_bindir}/aul_service.sh
%attr(0755,root,root) %{_bindir}/aul_service_test.sh
%attr(0755,root,root) %{_sysconfdir}/rc.d/rc3.d/S34launchpad_run
%attr(0755,root,root) %{_sysconfdir}/rc.d/rc4.d/S80launchpad_run
%config(noreplace) %attr(0644,root,app) /opt/dbspace/.mida.db
%config(noreplace) %attr(0644,root,app) /opt/dbspace/.mida.db-journal
%attr(0755,root,root) %{_bindir}/aul_mime.sh
%{_bindir}/aul_test
%{_bindir}/launch_app
/usr/share/aul/miregex/*
/usr/share/aul/service/*
/usr/share/aul/preload_list.txt
/usr/share/aul/preexec_list.txt
%{_bindir}/launchpad_preloading_preinitializing_daemon

%if %{with multi_user}
	%{_unitdir_user}/launchpad-preload.service
	%{_unitdir_user}/launchpad-preload.socket
	%{_unitdir_user}/ac.service
	%{_unitdir_user}/ac.socket
	%{_unitdir_user}/sockets.target.wants/launchpad-preload.socket
	%{_unitdir_user}/sockets.target.wants/ac.socket
%else
	%{_unitdir}/graphical.target.wants/launchpad-preload@app.service
	%{_unitdir}/graphical.target.wants/ac.service
	%{_unitdir}/launchpad-preload@.service
	%{_unitdir}/ac.service
	%{_unitdir}/ac.socket
%endif

/usr/bin/amd
/usr/bin/daemon-manager-release-agent
/usr/bin/daemon-manager-launch-agent

%files devel
%manifest %{name}.manifest
/usr/include/aul/*.h
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc
