Summary: A server daemon with D-Bus interface providing a server roles
Name: rolekit
Version: 0.0.4
Release: 1%{?dist}
URL: http://fedorahosted.org/rolekit
License: GPLv2+
Source0: https://fedorahosted.org/released/rolekit/%{name}-%{version}.tar.bz2
BuildArch: noarch
BuildRequires: gettext
BuildRequires: intltool
# glib2-devel is needed for gsettings.m4
BuildRequires: glib2, glib2-devel, dbus-devel
BuildRequires: systemd-units
BuildRequires: docbook-style-xsl
Requires: dbus-python
Requires: python-futures
Requires: python-slip-dbus
Requires: python-decorator
Requires: pygobject3-base
Requires: firewalld
Requires: systemd
Requires: NetworkManager
Requires: yum
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
rolekit is a server daemon that provides a D-Bus interface and server roles.

%prep
%setup -q

%build
%configure

%install
make install DESTDIR=%{buildroot}

#%find_lang %{name} --all-name

%post
%systemd_post rolekit.service

%preun
%systemd_preun rolekit.service

%postun
%systemd_postun_with_restart rolekit.service 


#%files -f %{name}.lang
%files
%doc COPYING README
%{_sbindir}/roled
%{_bindir}/rolectl
%defattr(-,root,root)
%dir %{_sysconfdir}/rolekit
%dir %{_sysconfdir}/rolekit/roles
%dir %{_prefix}/lib/rolekit
%dir %{_prefix}/lib/rolekit/roles
%{_prefix}/lib/rolekit/roles/*/*.py*
%config(noreplace) %{_sysconfdir}/sysconfig/rolekit
%{_unitdir}/rolekit.service
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/rolekit1.conf
%{_datadir}/polkit-1/actions/org.fedoraproject.rolekit1.policy
%{_datadir}/dbus-1/system-services/org.fedoraproject.rolekit1.service
%attr(0755,root,root) %dir %{python_sitelib}/rolekit
%attr(0755,root,root) %dir %{python_sitelib}/rolekit/config
%attr(0755,root,root) %dir %{python_sitelib}/rolekit/server
%attr(0755,root,root) %dir %{python_sitelib}/rolekit/server/io
%{python_sitelib}/rolekit/*.py*
%{python_sitelib}/rolekit/config/*.py*
%{python_sitelib}/rolekit/server/*.py*
%{python_sitelib}/rolekit/server/io/*.py*
%{_mandir}/man1/role*.1*
%{_mandir}/man5/role*.5*


%changelog
* Fri Aug 22 2014 Thomas Woerner <twoerner@redhat.com> 0.0.3-1
- Domain Controller: Add decommission routine
- Better trapping of non-ASCII output on subprocess
- Domain Controller deployment
- Make decommission asynchronous
- Improve exception logging
- DBusRole: New method get_name, using in RoleD.getNamedRole
- Enable logging of subprocess output
- Implement starting and stopping services, and use it in databaseserver
- New async.async_subprocess_future helper
- Changed async naming conventions
- Convert exceptions in D-Bus methods in async methods
- Added missing resetError message
- Several fixes and cleanups

* Mon Aug 11 2014 Thomas Woerner <twoerner@redhat.com> 0.0.2-1
- new instance support
- new rolectl command line tool
- new redeploy feature for instances
- new async support for deploy, start and stop D-Bus methods
- finalized states
- adapted D-Bus interface for instances
- dbus activation and auto-termination after some inactivity time
- dbus exception handling fixes
- build fixes and cleanups (distcheck, po/Makefile.in.in, ..)
- several fixes and cleanups

* Fri May 23 2014 Thomas Woerner <twoerner@redhat.com> 0.0.1-1
- initial package (proof of concept implementation)
