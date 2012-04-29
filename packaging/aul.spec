Name:       aul
Summary:    App utility library
Version:	0.0.169
Release:    2
Group:      System/Libraries
License:    Apache License, Version 2.0
Source0:    %{name}-%{version}.tar.gz

Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
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
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}/etc/init.d
install -m 755 launchpad_run %{buildroot}/etc/init.d
chmod +x %{buildroot}/usr/bin/aul_service.sh
chmod +x %{buildroot}/usr/bin/aul_service_test.sh


%post

/sbin/ldconfig
mkdir -p /etc/rc.d/rc3.d
mkdir -p /etc/rc.d/rc4.d
ln -sf /etc/init.d/launchpad_run /etc/rc.d/rc3.d/S35launchpad_run
ln -sf /etc/init.d/launchpad_run /etc/rc.d/rc4.d/S80launchpad_run

mkdir -p /opt/dbspace
sqlite3 /opt/dbspace/.mida.db < /opt/share/mida_db.sql
rm -rf /opt/share/mida_db.sql

chown 0:0 /usr/lib/libaul.so.0.1.0
chown 0:5000 /opt/dbspace/.mida.db
chown 0:5000 /opt/dbspace/.mida.db-journal

chmod 644 /usr/lib/libaul.so.0.1.0
chmod 664 /opt/dbspace/.mida.db
chmod 664 /opt/dbspace/.mida.db-journal

%postun -p /sbin/ldconfig

%files
/usr/lib/*.so.*
/etc/init.d/launchpad_run
/usr/bin/aul_service.sh
/usr/bin/aul_service_test.sh
/opt/share/mida_db.sql
/usr/bin/aul_mime.sh
/usr/bin/aul_test
/usr/bin/launch_app
/opt/share/miregex/*
/opt/share/service/*
/opt/share/preload_list.txt
/usr/bin/launchpad_preloading_preinitializing_daemon
/usr/bin/ac_daemon

%files devel
/usr/include/aul/*.h
/usr/lib/*.so
/usr/lib/pkgconfig/*.pc


