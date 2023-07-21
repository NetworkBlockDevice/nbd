Name:           nbd
Summary:        Network Block Device userland support files
Version:        3.25
Release:        0
License:        GPL-2.0-only
ExclusiveArch:  %{arm} aarch64 riscv64
Group:          System/Utilities
Source:         %{name}-%{version}.tar.gz
Source1001:     %{name}.manifest

BuildRequires: autoconf-archive
BuildRequires: bison
BuildRequires: flex
BuildRequires: pkgconfig(glib-2.0)

%description
Network Block Device is a Linux driver that enables using a file served
by nbd-server via a network as a block device. nbd-client program is required
to set up connection between a client and a server.

This package contains nbd-trdump and nbd-trplay tools.

%package server
Summary: Network Block Device userland support files (server)
%description server
Network Block Device is a Linux driver that enables using a file served
by nbd-server via a network as a block device. nbd-client program is required
to set up connection between a client and a server.

This package contains nbd-server program.

%package client
Summary: Network Block Device userland support files (client)
%description client
Network Block Device is a Linux driver that enables using a file served
by nbd-server via a network as a block device. nbd-client program is required
to set up connection between a client and a server.

This package contains nbd-client program.

%prep
%setup -q

%build
cp %{SOURCE1001} .
cat <<EOF > support/genver.sh
#!/bin/sh

echo %{version}-%{release}
EOF

autoreconf -f -i
%configure --disable-manpages
%__make

%install
%make_install

%files
%manifest nbd.manifest
%license COPYING
%{_bindir}/nbd-trdump
%{_bindir}/nbd-trplay

%files server
%manifest nbd.manifest
%license COPYING
%{_bindir}/nbd-server

%files client
%manifest nbd.manifest
%license COPYING
%{_sbindir}/nbd-client
