#accel-config test

The test command is an option to test all the library code of accel-config,
including set and get libaccfg functions for all components in dsa device, set
large wq to exceed max total size in dsa, test the create-mdev and remove-mdev
on shared wq and dedicated wq.

Build
=====
To enable test in the accel-config utility, building steps are following:

```
./autogen.sh
./configure CFLAGS='-g -O2' --prefix=/usr --sysconfdir=/etc --libdir=/usr/lib64
--enable-test=yes
make
sudo make install
```

Option
======
'accel-config test' [<options>]

Options can be specified to set the log level (default is LOG DEBUG), or force
the test to run without subject to the limit of kernel version.

-l::
--log-level=::
	set the log level, by default it is LOG_DEBUG.

-f::
--force=::
	force action, by default test the library code requires 5.6.0 kernel.

Examples
========
The following shows an example of using "accel-config test" with force.

```
# accel-config test -f
run test libaccfg
configure device 0
configure group0.0
configure wq0.0
configure engine0.0
configure engine0.1
configure group0.1
configure wq0.1
configure wq0.2
configure wq0.3
configure engine0.2
configure engine0.3
check device0
check group0.0
check group0.1
check wq0.0
check wq0.1
check wq0.2
check wq0.3
check engine0.0
check engine0.1
check engine0.2
check engine0.3
test 0: test the set and get libaccfg functions for components passed successfully
configure device 1
configure group1.3
configure wq1.2
configure wq1.3
configure wq1.4
test 1: set large wq to exceed max total size in dsa passed successfully
wq not enabled
uuid 7a0dca6f-02fe-4cd3-a7ee-9a767883dc08 successfully attached to wq0.2
uuid d6a87782-8736-4166-aba3-c6580269f186 successfully attached to wq0.2
uuid 4d0758a3-7ff1-42ec-9979-ba046a1f5722 successfully attached to wq0.2
uuid c0aa9cd2-3d9d-4cf9-a085-f5bb0f1e9fe0 successfully attached to wq0.2
uuid 57a5e7a6-cd7d-4fdb-b764-dc0b5fceb047 successfully attached to wq0.2
successfully removed the saved uuid c0aa9cd2-3d9d-4cf9-a085-f5bb0f1e9fe0 in wq
successfully removed the rest uuid in shared wq
wq0.0 is disabled already
wq0.1 is disabled already
wq0.3 is disabled already
wq0.4 is disabled already
wq0.5 is disabled already
wq0.6 is disabled already
wq0.7 is disabled already
test 2: test the create-mdev and remove-mdev on shared wq passed successfully
configure device 0
configure group0.0
configure wq0.0
configure engine0.0
configure engine0.1
configure group0.1
configure wq0.1
configure wq0.2
configure wq0.3
configure engine0.2
configure engine0.3
wq not enabled
uuid 97fc3e6a-9cb3-46d7-93e6-7b64ebb0d0dd successfully attached to wq0.3
successfully removed the saved uuid 97fc3e6a-9cb3-46d7-93e6-7b64ebb0d0dd in wq
wq0.0 is disabled already
wq0.1 is disabled already
wq0.2 is disabled already
wq0.3 is disabled already
wq0.4 is disabled already
wq0.5 is disabled already
wq0.6 is disabled already
wq0.7 is disabled already
test 3: test the create-mdev and remove-mdev on dedicated wq passed successfully
test-libaccfg: PASS
SUCCESS!
```
