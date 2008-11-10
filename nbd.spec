%def_disable debug
%def_enable syslog
%def_enable lfs
%def_disable sdp
%def_with gznbd
%def_with static_client

%define Name NBD
Name: nbd
Version: 2.9.11
Release: alt2
Summary: Tools for using the Network Block Device
License: GPL
Group: Networking/Other
URL: http://%name.sourceforge.net/
Source0: %name-%version.tar.bz2
Source1: %name.init
Patch0: %name-2.9.11-configure.patch
Patch1: %name-2.9.11-types.patch
Patch2: %name-2.9.11-alt-doc.patch
BuildRequires: glib2-devel >= 2.6.0
%{?_with_gznbd:BuildRequires: zlib-devel}
%{?_with_static_client:BuildRequires: dietlibc}

%description
%Name contains the tools needed to export a network block device and to
use a network block device. The %name module is part of the 2.2 kernels
and higher.
You can use the network block device to swap over the net, which is
particularly useful for diskless workstations.


%package doc
Summary: %Name docs
Group: Documentation

%description doc
%Name docs.


%package server
Summary: %Name server
Group: Networking/Other

%description server
%Name server needed to export a network block device.


%package client
Summary: %Name client
Group: Networking/Other

%description client
%Name client needed to use a network block device.
You can use the network block device to swap over the net, which is
particularly useful for diskless workstations.


%if_with static_client
%package client-static
Summary: %Name client
Group: Networking/Other

%description client-static
%Name client needed to use a network block device.
You can use the network block device to swap over the net, which is
particularly useful for diskless workstations.

This package contains static %name-client (can be used for initrd).
%endif


%prep
%setup
%patch0 -p1
%patch1 -p1
%patch2 -p1


%build
%autoreconf
%configure \
    %{subst_enable debug} \
    %{subst_enable syslog} \
    %{subst_enable lfs} \
    %{subst_enable sdp}
%if_with static_client
make CC="diet %__cc" CFLAGS="%optflags -Os" %name-client
mv %name-client{,.static}
%make_build clean
%endif
%make_build
%{?_with_gznbd:%make_build -C gznbd CFLAGS="%optflags -DMY_NAME='\"gznbd\"'"}


%install
install -d %buildroot%_sysconfdir/%name-server
touch %buildroot%_sysconfdir/%name-server/config
%make_install DESTDIR=%buildroot install
%{?_with_static_client:install -m 0755 %name-client.static %buildroot%_sbindir/}
%{?_with_gznbd:install -m 0755 gznbd/gznbd %buildroot%_bindir/}
install -D -m 0755 %SOURCE1 %buildroot%_initdir/%name


%post -n %name-server
%post_service %name ||:


%preun -n %name-server
%preun_service %name ||:


%files doc
%doc README simple_test


%files server
%_bindir/*
%dir %_sysconfdir/%name-server
%config(noreplace) %_sysconfdir/%name-server/config
%_man1dir/*
%_man5dir/*
%_initdir/*


%files client
%_sbindir/%name-client
%_man8dir/*


%if_with static_client
%files client-static
%_sbindir/%name-client.static
%endif


%changelog
* Tue Jun 10 2008 Led <led@altlinux.ru> 2.9.11-alt2
- added:
  + %name-2.9.11-configure.patch
  + %name-2.9.11-alt-doc.patch
- updated %name-2.9.11-types.patch

* Thu May 08 2008 Led <led@altlinux.ru> 2.9.11-alt1
- 2.9.11
- removed %name-2.9.6-gznbd.patch
- updated %name-2.9.11-types.patch

* Mon Dec 10 2007 Led <led@altlinux.ru> 2.9.9-alt1
- 2.9.9
- removed nbd-2.9.8-close.patch

* Fri Nov 09 2007 Led <led@altlinux.ru> 2.9.8-alt2
- added %name-2.9.8-close.patch

* Mon Oct 29 2007 Led <led@altlinux.ru> 2.9.8-alt1
- 2.9.8
- removed %name-2.9.7-prerun.patch (fixed in upstream)

* Thu Oct 18 2007 Led <led@altlinux.ru> 2.9.7-alt4
- fixed init-script for %name-server

* Mon Oct 15 2007 Led <led@altlinux.ru> 2.9.7-alt3
- cleaned up spec
- added init-script for %name-server

* Sun Oct 14 2007 Led <led@altlinux.ru> 2.9.7-alt2
- added %name-client.static
- added %name-2.9.7-prerun.patch

* Fri Sep 21 2007 Led <led@altlinux.ru> 2.9.7-alt1
- 2.9.7

* Mon Aug 06 2007 Led <led@altlinux.ru> 2.9.6-alt1
- 2.9.6
- updated %name-2.9.6-gznbd.patch

* Sat Jun 16 2007 Led <led@altlinux.ru> 2.9.3-alt1
- 2.9.3

* Fri Mar 16 2007 Led <led@altlinux.ru> 2.9.0-alt0.1
- initial build
