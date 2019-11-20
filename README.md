# accel-config
Utility library for controlling and configuring DSA (Data-Streaming Accelerator)
sub-system in the Linux kernel


Build
=====

```
./autogen.sh
./configure CFLAGS='-g -O2' --prefix=/usr --sysconfdir=/etc --libdir=/usr/lib64
make
make check
sudo make install
```

There are a number of packages required for the build steps that may not
be installed by default.   For information about the required packages,
see the "BuildRequires:" lines in accel-config.spec.in.
# idxd-config
