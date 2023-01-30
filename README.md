mod_log_ipmask
==============

The mod_log_ipmask module is designed to work with version 2.4 of the Apache
HTTP Server. It extends the mod_log_config module by overriding the `%a` and
`%h` format strings in order to limit the number of IP address bits that are
included in log files. This is intended for applications where partial logging
of IP addresses is desired, but full IP addresses may not be logged due to
privacy concerns.


Installation
------------

On Debian-based systems, a package can be built from source by running `debuild`
in the source tree. Subsequently, the generated `.deb` package can be installed
with `dpkg`. The module has been developped for Ubuntu 16.04 LTS. When building
it on other Debian-based distributions, slight modifications to the `Makefile`
may be necessary.

On other systems, the module can be built by running `make` and installed by
running `make install`. The `Makefile` may need to be adapted if the
configuration of the target system differs from Ubuntu 16.04 LTS (e.g. different
Apache installation path, different compiler name or flags).


Configuration
-------------

When using the Debian package, the module is automatically enabled during
installation. The default configuration file can be found in
`/etc/apache2/mods-available/log_ipmask.conf`.

When installing the module using `make install` the following line needs to be
added to the Apache HTTP Server configuration file in order to load the module.

```
LoadModule log_ipmask_module /usr/lib/apache2/modules/mod_log_ipmask.so
```

Obviously, the path to the module DSO file may need to be adjusted.

The default configuration file distributed with the Debian package contains the
following configuration directives:

```
LogDefaultIPv4Mask 24
LogDefaultIPv6Mask 56
```

This limits the logging of IPv4 addresses to their first 24 bits and the logging
of IPv6 addresses to their first 56 bits. If these directives are not specified,
the module logs the full IP addresses by default.

The `LogDefaultIPv4Mask` and `LogDefaultIPv6Mask` directives may be used on the
server config or virtual host levels. Settings specified on the virtual host
level override settings specified on the server config level.

In order to not log any bits of the IP address, the mask can be set to zero.
This results in the address `0.0.0.0` being logged for IPv4 addresses and the
address `::` being logged for IPv6 addresses. In order to enable the logging of
full IP addresses, `LogDefaultIPv4Mask` can be set to `32` and
`LogDefaultIPv6Mask` can be set to `128`. These are also the default settings if
the directives are not specified at all.

The mask can also be configured on a per-log basis by adding the mask to the
parameters of the `%a` or `%h` format string.

Examples:

- `%{8|16}a` logs the first 8 bits of IPv4 addresses and the first 16 bits of
  IPv6 addresses.
- `%{c|8|16}a` logs the first 8 bits of IPv4 addresses and the first 16 bits of
  IPv6 addresses, but uses the peer IP address of the connection (as
  described in the documentation of
  [mod_log_config](http://httpd.apache.org/docs/2.4/mod/mod_log_config.html)).
- `%a` logs the address according to the settings specified by
  `LogDefaultIPv4Mask` and `LogDefaultIPv6Mask`.
- `%{c}a` logs the address according to the settings specified by
  `LogDefaultIPv4Mask` and `LogDefaultIPv6Mask`, but uses the peer IP address of
  the connection (as described in the documentation of
  [mod_log_config](http://httpd.apache.org/docs/2.4/mod/mod_log_config.html)).
- `%{8|16}h` logs the first 8 bits of IPv4 addresses and the first 16 bits of
  IPv6 addresses. If the remote host name has been resolved, it is logged as is.
- `%a` logs the address according to the settings specified by
  `LogDefaultIPv4Mask` and `LogDefaultIPv6Mask`.  If the remote host name has
  been resolved, it is logged as is.

### Error log

If you also want to anonymize IP addresses in the error log, you have to use the
`ErrorLogFormat` directive. If you do not use this directive, the logging
happens through a code path that cannot be intercepted by mod_log_ipmask.

The following directive should produce log output that is similar to the default
format, but honoring the masks specified through `LogDefaultIPv4Mask` and
`LogDefaultIPv6Mask`:

```
ErrorLogFormat "[%t] [%m:%l] [pid\ %P:tid\ %T] [client\ %a] %E: %M"
```

Like for the `LogFormat` directive, you can also specificy the mask inside the
formatting string. For example:

```
ErrorLogFormat "[%t] [%m:%l] [pid\ %P:tid\ %T] [client\ %{8|16}a] %E: %M"
```


Limitations
-----------

When using the `%h` format string, only IP addresses are masked. If the IP
address has been resolved into a hostname, the hostname is kept as-is.


Trivia
------

Despite its name, this module does not share any code with the mod_log_ipmask
module from https://github.com/webfactory/mod_log_ipmask/.
