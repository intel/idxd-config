#accel-config test

The test command is an option to test all the library code of accel-config,
including set and get libaccfg functions for all components in dsa device, set
large wq to exceed max total size in dsa.

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

Options can be specified to set the log level (default is LOG DEBUG).

-l::
--log-level=::
	set the log level, by default it is LOG_DEBUG.

Examples
========
The following shows an example of using "accel-config test".

```
# accel-config test
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
test-libaccfg: PASS
SUCCESS!
```
