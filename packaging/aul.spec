%bcond_with x
%bcond_with wayland

Name:       aul
Summary:    App utility library
Version:    0.0.300
Release:    1
Group:      Application Framework/Libraries
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: %{name}.manifest

Requires(post):   /sbin/ldconfig
Requires(post):   /usr/bin/systemctl
Requires(postun): /sbin/ldconfig
Requires(postun): /usr/bin/systemctl
Requires(preun):  /usr/bin/systemctl
Requires:   tizen-platform-config
Requires:   amd

BuildRequires:  cmake
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  xdgmime-devel, pkgconfig(xdgmime)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  libattr-devel
BuildRequires:  pkgconfig(libtzplatform-config)
BuildRequires:  pkgconfig(libsystemd-daemon)
BuildRequires:  pkgconfig(capi-system-info)
BuildRequires:  pkgconfig(iniparser)
BuildRequires:  pkgconfig(sqlite3)
%if %{with wayland}
BuildRequires:  pkgconfig(ecore-wayland)
BuildRequires:  pkgconfig(wayland-client)
BuildRequires:  pkgconfig(tizen-extension-client)
%endif

%description
Application utility library

%package devel
Summary:    App utility library (devel)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
Application utility library (devel)

%package test
Summary:    App utility test tools
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description test
Application utility library (test tools)


%prep
%setup -q
sed -i 's|TZ_SYS_DB|%{TZ_SYS_DB}|g' %{SOURCE1001}
cp %{SOURCE1001} .

%build
%if 0%{?simulator}
CFLAGS="%{optflags} -D__emul__"; export CFLAGS
%endif

MAJORVER=`echo %{version} | awk 'BEGIN {FS="."}{print $1}'`
%cmake . -DFULLVER=%{version} -DMAJORVER=${MAJORVER} \
%if %{with wayland}
-Dwith_wayland=TRUE\
%endif
%if %{with x}
-Dwith_x11=TRUE\
%endif

%__make %{?_smp_mflags}

sqlite3 .appsvc.db < ./data/appsvc_db.sql

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}%{_tmpfilesdir}
mkdir -p %{buildroot}%{_sysconfdir}/skel/.applications/dbspace
install -m 0644 .appsvc.db %{buildroot}%{_sysconfdir}/skel/.applications/dbspace/.appsvc.db

mkdir -p %{buildroot}%{_datadir}/appsvc
cp -R %{_builddir}/%{name}-%{version}/alias/* %{buildroot}%{_datadir}/appsvc

%preun

%post
/sbin/ldconfig

chsmack -a 'User::Home' %{_sysconfdir}/skel/.applications/dbspace/.appsvc.db

%postun
/sbin/ldconfig

%files
%license LICENSE
%manifest %{name}.manifest
%attr(0644,root,root) %{_libdir}/libaul.so.*
%{_bindir}/aul_test
%{_bindir}/app_launcher
%{_bindir}/appgroup_info
%{_bindir}/launch_app
%{_bindir}/appid2pid
%{_bindir}/launch_debug
%{_datadir}/aul/miregex/*
%{_datadir}/aul/preload_list.txt
%{_datadir}/aul/preexec_list.txt
%{_datadir}/appsvc/*
%{_sysconfdir}/skel/.applications/dbspace/.appsvc.db

%files test
%{_bindir}/open_app

%files devel
%{_includedir}/aul/*.h
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc
