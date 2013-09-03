%bcond_without privacy-manager-client
%bcond_with multi_user

Name:       aul
Summary:    App utility library
Version:    0.0.266
Release:    1
Group:      Application Framework/Libraries
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source101:  launchpad-preload@.service
Source102:  ac.service
Source103:  launchpad-preload_user.service
Source104:  ac_user.service
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

%description
Application utility library

%package devel
Summary:    App utility library (devel)
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

mkdir -p %{buildroot}/opt/dbspace
sqlite3 %{buildroot}/opt/dbspace/.mida.db < %{buildroot}/usr/share/aul/mida_db.sql
rm -rf %{buildroot}/usr/share/aul/mida_db.sql
%if %{with multi_user}
mkdir -p %{buildroot}/%{_unitdir_user}/tizen-middleware.target.wants
install -m 0644 %SOURCE103 %{buildroot}/%{_unitdir_user}/launchpad-preload.service
install -m 0644 %SOURCE104 %{buildroot}/%{_unitdir_user}/ac.service
ln -s ../launchpad-preload.service %{buildroot}/%{_unitdir_user}/tizen-middleware.target.wants/launchpad-preload.service
ln -s ../ac.service %{buildroot}/%{_unitdir_user}/tizen-middleware.target.wants/ac.service
%else
mkdir -p %{buildroot}/%{_unitdir}/graphical.target.wants
install -m 0644 %SOURCE101 %{buildroot}/%{_unitdir}/launchpad-preload@.service
install -m 0644 %SOURCE102 %{buildroot}/%{_unitdir}/ac.service
ln -s ../launchpad-preload@.service %{buildroot}/%{_unitdir}/graphical.target.wants/launchpad-preload@app.service
ln -s ../ac.service %{buildroot}/%{_unitdir}/graphical.target.wants/ac.service
%endif

%preun
%if !%{with multi_user}
if [ $1 == 0 ]; then
    systemctl stop launchpad-preload@app.service
    systemctl stop ac.service
fi
%endif

%post
/sbin/ldconfig
systemctl daemon-reload
%if !%{with multi_user}
if [ $1 == 1 ]; then
    systemctl restart launchpad-preload@app.service
    systemctl restart ac.service
fi
%endif

%postun
/sbin/ldconfig
%if !%{with multi_user}
systemctl daemon-reload
%endif

%files
%manifest %{name}.manifest
%attr(0644,root,root) %{_libdir}/libaul.so.0
%attr(0644,root,root) %{_libdir}/libaul.so.0.1.0
%attr(0755,root,root) %{_bindir}/aul_service.sh
%attr(0755,root,root) %{_bindir}/aul_service_test.sh
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
%{_unitdir_user}/tizen-middleware.target.wants/launchpad-preload.service
%{_unitdir_user}/tizen-middleware.target.wants/ac.service
%{_unitdir_user}/launchpad-preload.service
%{_unitdir_user}/ac.service
%else
%{_unitdir}/graphical.target.wants/launchpad-preload@app.service
%{_unitdir}/graphical.target.wants/ac.service
%{_unitdir}/launchpad-preload@.service
%{_unitdir}/ac.service
%endif


/usr/bin/amd
/usr/bin/daemon-manager-release-agent
/usr/bin/daemon-manager-launch-agent

%files devel
%manifest %{name}.manifest
/usr/include/aul/*.h
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc
