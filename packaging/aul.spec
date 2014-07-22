Name:       aul
Summary:    App utility library
Version:    0.0.300
Release:    1
Group:      System/Libraries
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source101:  launchpad-preload@.service
Source102:  ac.service
Source103:  amd_session_agent.service
Source1001: %{name}.manifest

Requires(post): /sbin/ldconfig
Requires(post): /usr/bin/systemctl
Requires(postun): /sbin/ldconfig
Requires(postun): /usr/bin/systemctl
Requires(preun): /usr/bin/systemctl

BuildRequires:  cmake
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(ail)
BuildRequires:  xdgmime-devel, pkgconfig(xdgmime)
BuildRequires:  pkgconfig(libprivilege-control)
BuildRequires:  pkgconfig(app-checker)
BuildRequires:  pkgconfig(app-checker-server)
BuildRequires:  pkgconfig(rua)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  libattr-devel
BuildRequires:  pkgconfig(privacy-manager-client)
BuildRequires:  pkgconfig(libtzplatform-config)

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
sed -i 's|TZ_SYS_DB|%{TZ_SYS_DB}|g' %{SOURCE1001}
cp %{SOURCE1001} .

%build
%if 0%{?simulator}
CFLAGS="%{optflags} -D__emul__"; export CFLAGS
%endif

%cmake .

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

mkdir -p %{buildroot}%{TZ_SYS_DB}
sqlite3 %{buildroot}%{TZ_SYS_DB}/.mida.db < %{buildroot}/usr/share/aul/mida_db.sql
rm -rf %{buildroot}/usr/share/aul/mida_db.sql

mkdir -p %{buildroot}/usr/lib/systemd/system/graphical.target.wants
mkdir -p %{buildroot}/usr/lib/systemd/user/default.target.wants
install -m 0644 %SOURCE101 %{buildroot}/usr/lib/systemd/system/launchpad-preload@.service
install -m 0644 %SOURCE102 %{buildroot}/usr/lib/systemd/system/ac.service
ln -s ../launchpad-preload@.service %{buildroot}/usr/lib/systemd/system/graphical.target.wants/launchpad-preload@5000.service
ln -s ../ac.service %{buildroot}/usr/lib/systemd/system/graphical.target.wants/ac.service

install -m 0644 %SOURCE103 %{buildroot}/usr/lib/systemd/user/amd_session_agent.service
ln -s ../amd_session_agent.service %{buildroot}/usr/lib/systemd/user/default.target.wants/amd_session_agent.service

%preun
if [ $1 == 0 ]; then
    systemctl stop launchpad-preload@5000.service
    systemctl stop ac.service
fi

%post
/sbin/ldconfig
systemctl daemon-reload
if [ $1 == 1 ]; then
    systemctl restart launchpad-preload@5000.service
    systemctl restart ac.service
fi

%postun
/sbin/ldconfig
systemctl daemon-reload

%files
%license LICENSE
%manifest %{name}.manifest
%attr(0644,root,root) %{_libdir}/libaul.so.0
%attr(0644,root,root) %{_libdir}/libaul.so.0.1.0
%{_sysconfdir}/init.d/launchpad_run
%attr(0755,root,root) %{_bindir}/aul_service.sh
%attr(0755,root,root) %{_bindir}/aul_service_test.sh
%attr(0755,root,root) %{_sysconfdir}/rc.d/rc3.d/S34launchpad_run
%attr(0755,root,root) %{_sysconfdir}/rc.d/rc4.d/S80launchpad_run
%config(noreplace) %attr(0644,root,%{TZ_SYS_USER_GROUP}) %{TZ_SYS_DB}/.mida.db
%config(noreplace) %attr(0644,root,%{TZ_SYS_USER_GROUP}) %{TZ_SYS_DB}/.mida.db-journal
%attr(0755,root,root) %{_bindir}/aul_mime.sh
%{_bindir}/aul_test
%{_bindir}/launch_app
%{_bindir}/open_app
%{_bindir}/amd_session_agent
/usr/share/aul/miregex/*
/usr/share/aul/service/*
/usr/share/aul/preload_list.txt
/usr/share/aul/preexec_list.txt
/usr/lib/systemd/system/graphical.target.wants/launchpad-preload@5000.service
/usr/lib/systemd/system/graphical.target.wants/ac.service
/usr/lib/systemd/system/launchpad-preload@.service
/usr/lib/systemd/system/ac.service
/usr/lib/systemd/user/amd_session_agent.service
/usr/lib/systemd/user/default.target.wants/amd_session_agent.service
/usr/bin/amd
/usr/bin/daemon-manager-release-agent
/usr/bin/daemon-manager-launch-agent

%files devel
/usr/include/aul/*.h
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc
