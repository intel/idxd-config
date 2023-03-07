# accel-config

Utility library for controlling and configuring DSA (Intel® Data Streaming
Accelerator Architecture) and IAA (Intel® Analytics Accelerator Architecture)
sub-systems in the Linux kernel

## Resolve dependencies

### Fedora, RHEL, CentOS
```bash
yum groupinstall "Development Tools"
yum install autoconf automake libtool pkgconf rpm-build rpmdevtools
yum install asciidoc xmlto libuuid-devel json-c-devel zlib-devel openssl-devel
```
### Debian
```bash
apt install build-essential
apt install autoconf automake autotools-dev libtool pkgconf asciidoc xmlto
apt install uuid-dev libjson-c-dev libkeyutils-dev libz-dev libssl-dev
apt install debhelper devscripts debmake quilt fakeroot lintian asciidoctor
apt install file gnupg patch patchutils
```

## Build

```bash
./autogen.sh
./configure CFLAGS='-g -O2' --prefix=/usr --sysconfdir=/etc --libdir=/usr/lib64
make
make check
sudo make install
```

Build with test

```bash
./autogen.sh
./configure CFLAGS='-g -O2' --prefix=/usr --sysconfdir=/etc \
    --libdir=/usr/lib64 --enable-test=yes
make
make check
sudo make install
```

## Build RPM

```bash
mkdir -p ${HOME}/rpmbuild/SOURCES
./autogen.sh
./configure CFLAGS='-g -O2' --prefix=/usr --sysconfdir=/etc --libdir=/usr/lib64
make rhel/accfg.spec
./rpmbuild.sh
```

Build as RPM package with test

```bash
mkdir -p ${HOME}/rpmbuild/SOURCES
./autogen.sh
./configure CFLAGS='-g -O2' --prefix=/usr --sysconfdir=/etc \
    --libdir=/usr/lib64 --enable-test=yes
make rhel/accfg-test.spec
./rpmbuild-test.sh
```

There are a number of packages required for the build steps that may not
be installed by default. For information about the required packages,
see the "BuildRequires:" lines in accfg.spec.in and accfg-test.spec.in.

## Build Debian Package
```bash
export DEBEMAIL="your.email@example.org"
export DEBFULLNAME="Firstname Lastname"
./autogen.sh
./configure CFLAGS='-g -O2' --prefix=/usr --sysconfdir=/etc \
    --libdir=/usr/lib64 --enable-test=yes

./debdch.sh
(Run dch -r and edit debian/changelog as necessary)

./debbuild.sh

Debian package components would be created in ./debpkg

debian/changelog changes should be committed
```
