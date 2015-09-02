Summary: A server daemon with D-Bus interface providing a server roles
Name: rolekit
Version: 0.3.93
Release: 0%{?dist}
URL: https://github.com/libre-server/rolekit
License: GPLv2+
# fixme, point to github once the tarballs are there
# https://github.com/libre-server/rolekit/issues/37
Source0: https://fedorahosted.org/released/rolekit/%{name}-%{version}.tar.bz2
BuildArch: noarch
BuildRequires: gettext
BuildRequires: intltool
# glib2-devel is needed for gsettings.m4
BuildRequires: glib2, glib2-devel, dbus-devel
BuildRequires: systemd-units
BuildRequires: docbook-style-xsl
BuildRequires: polkit-devel

BuildRequires: python3-devel
Requires: python3-dbus
Requires: python3-slip-dbus
Requires: python3-decorator

%if 0%{?fedora} >= 23
Requires: python3-gobject-base
%else
Requires: python3-gobject
%endif

Requires: python3-firewall
Requires: python-IPy-python3

Requires: firewalld
Requires: systemd
Requires: NetworkManager
Requires: dnf
Requires: polkit
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
%{__mkdir_p} $RPM_BUILD_ROOT/%{_datadir}/bash-completion/completions
make install DESTDIR=%{buildroot}

# Move the testrole into documentation instead of the live system
%{__mkdir_p} $RPM_BUILD_ROOT/%{_docdir}/examples/
%{__mv} $RPM_BUILD_ROOT/%{_prefix}/lib/rolekit/roles/testrole \
        $RPM_BUILD_ROOT/%{_docdir}/examples/


#%find_lang %{name} --all-name

%post
%systemd_post rolekit.service

%preun
%systemd_preun rolekit.service

%postun
%systemd_postun_with_restart rolekit.service


#%files -f %{name}.lang
%files
%doc COPYING README.md
%{_sbindir}/roled
%{_bindir}/rolectl
%defattr(-,root,root)
%dir %{_sysconfdir}/rolekit
%dir %{_sysconfdir}/rolekit/roles
%dir %{_sysconfdir}/rolekit/deferredroles
%dir %{_prefix}/lib/rolekit
%dir %{_prefix}/lib/rolekit/roles
%{_prefix}/lib/rolekit/roles/domaincontroller/*.py*

%{_prefix}/lib/rolekit/roles/databaseserver/*.py*
%{_prefix}/lib/rolekit/roles/databaseserver/tools/rk_db_setpwd.py*

%{_prefix}/lib/rolekit/roles/memcache/*.py*

%config(noreplace) %{_sysconfdir}/sysconfig/rolekit
%{_unitdir}/rolekit.service
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/rolekit1.conf
%{_datadir}/polkit-1/actions/org.fedoraproject.rolekit1.policy
%{_datadir}/dbus-1/system-services/org.fedoraproject.rolekit1.service
%attr(0755,root,root) %dir %{python3_sitelib}/rolekit
%attr(0755,root,root) %dir %{python3_sitelib}/rolekit/config
%attr(0755,root,root) %dir %{python3_sitelib}/rolekit/server
%attr(0755,root,root) %dir %{python3_sitelib}/rolekit/server/io
%{python3_sitelib}/rolekit/*.py*
%{python3_sitelib}/rolekit/config/*.py*
%{python3_sitelib}/rolekit/rolectl/*.py*
%{python3_sitelib}/rolekit/server/*.py*
%{python3_sitelib}/rolekit/server/io/*.py*

%{python3_sitelib}/rolekit/config/__pycache__/*.py*
%{python3_sitelib}/rolekit/__pycache__/*.py*
%{python3_sitelib}/rolekit/rolectl/__pycache__/*.py*
%{python3_sitelib}/rolekit/server/__pycache__/*.py*
%{python3_sitelib}/rolekit/server/io/__pycache__/*.py*

%{_mandir}/man1/role*.1*
%{_mandir}/man5/role*.5*
%{_docdir}/examples/

%dir %{_datadir}/bash-completion/completions
%{_datadir}/bash-completion/completions/rolectl


%changelog
* Thu Jul 09 2015 Stephen Gallagher <sgallagh@redhat.com> 0.4.0-0.dev
- Switch to python3 on platforms that support it
- Add support for older versions of postgresql

* Tue Apr 07 2015 Stephen Gallagher <sgallagh@redhat.com> 0.3.2-1
- Fix bug with setting database owner password

* Tue Mar 31 2015 Stephen Gallagher <sgallagh@redhat.com> 0.3.1-1
- Don't create an instance on input value failure
- DB Role: don't consider ERROR instances when checking for first-instance
  deployment.

* Thu Mar 26 2015 Stephen Gallagher <sgallagh@redhat.com> 0.3.0-1
- Support for the Database Server Role
- New verbose option for 'rolectl list instances'
- Manpage cleanups

* Mon Feb 23 2015  0.2.2-1
- Switch to DNF as the package manager

* Thu Jan 22 2015 Stephen Gallagher <sgallagh@redhat.com> 0.2.0-1
- New Database Server Role
- Enhancements to async.py for impersonation and passing stdin

* Mon Nov 17 2014 Stephen Gallagher <sgallagh@redhat.com> 0.1.2-1
- More documentation updates
- Allow roles to override MAX_INSTANCES
- Remove the instance if settings-verification fails

* Mon Nov 17 2014 Stephen Gallagher <sgallagh@redhat.com> 0.1.1-1
- Improve documentation
- Remove incomplete database server role
- Add bash-completion file
- Bug-fixes

* Mon Oct 13 2014 Thomas Woerner <twoerner@redhat.com> 0.1.0-1
- Update role instance state on roled wakup.
- New package and group installation during role deployment
- RoleBase: Use systemd targets for start() and stop()
- New support for systemd targets
- RoleBase: Handle NULL types
- Domain Controller: Export properties
- Added missing requires for firewalld, systemd, NetworkManager and yum
- New --settings-file option for rolectl, replaces --set option
- New firewall handling
- Property fixes, new property checks
- Bug fixes

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
