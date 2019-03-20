# accel-config

Utility library for controlling and configuring DSA (Data-Streaming Accelerator)
sub-system in the Linux kernel

## Resolve dependencies

```bash
yum groupinstall "Development Tools"
yum install autoconf automake libtool pkgconf rpm-build rpmdevtools
yum install asciidoc xmlto json-c-devel kmod-devel libudev-devel
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
