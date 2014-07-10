sconfdir = $(sysconfdir)/rolekit
prefixlibdir = ${prefix}/lib/rolekit

polkit1_action_FILES = org.fedoraproject.rolekit1.policy.in
polkit1_actiondir = $(datadir)/polkit-1/actions
polkit1_action_DATA = $(polkit1_action_FILES:.in=)

dbus_policydir = $(sysconfdir)/dbus-1/system.d
dist_dbus_policy_DATA = rolekit1.conf


BUILT_SOURCES = \
	$(polkit1_action_DATA) \
	rolekit.service

@INTLTOOL_POLICY_RULE@
@INTLTOOL_XML_NOMERGE_RULE@
@GSETTINGS_RULES@

all: $(polkit1_action_DATA)

CLEANFILES = *~ *\# .\#* rolekit.service roles/*/*~ roles/*/*.py?*

DISTCLEANFILES = \
	$(polkit1_action_DATA)

EXTRA_DIST = \
	$(polkit1_action_FILES) \
	rolekit.init \
	rolekit.service.in \
	rolekit.sysconfig \
	roles/testrole/role.py

INSTALL_TARGETS = install-config
UNINSTALL_TARGETS = uninstall-config

if USE_SYSTEMD
INSTALL_TARGETS += install-service
UNINSTALL_TARGETS += uninstall-service
else
INSTALL_TARGETS += install-init
UNINSTALL_TARGETS += uninstall-init
endif

if INSTALL_SYSCONFIG
INSTALL_TARGETS += install-sysconfig
UNINSTALL_TARGETS += uninstall-sysconfig
endif

edit = sed \
	-e 's|@bindir[@]|$(bindir)|g' \
	-e 's|@sbindir[@]|$(sbindir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	-e 's|@localstatedir[@]|$(localstatedir)|g'

rolekit.service: rolekit.service.in
	$(edit) $< >$@

install-sysconfig:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/sysconfig
	$(INSTALL_DATA) $(srcdir)/rolekit.sysconfig $(DESTDIR)$(sysconfdir)/sysconfig/rolekit

uninstall-sysconfig:
	rm -f $(DESTDIR)$(sysconfdir)/sysconfig/rolekit
	rmdir $(DESTDIR)$(sysconfdir)/sysconfig || :

install-init: install-sysconfig
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/rc.d/init.d
	$(INSTALL_SCRIPT) $(srcdir)/rolekit.init $(DESTDIR)$(sysconfdir)/rc.d/init.d/rolekit

uninstall-init: uninstall-sysconfig
	rm -f $(DESTDIR)$(sysconfdir)/rc.d/init.d/rolekit
	rmdir $(DESTDIR)$(sysconfdir)/rc.d/init.d || :

install-service: install-sysconfig
	$(MKDIR_P) $(DESTDIR)$(SYSTEMD_UNITDIR)
	$(INSTALL_DATA) rolekit.service $(DESTDIR)$(SYSTEMD_UNITDIR)/rolekit.service

uninstall-service: uninstall-sysconfig
	rm -f $(DESTDIR)$(SYSTEMD_UNITDIR)/rolekit.service
	rmdir $(DESTDIR)$(SYSTEMD_UNITDIR) || :

install-config:
	$(MKDIR_P) $(DESTDIR)$(sconfdir)
	$(MKDIR_P) $(DESTDIR)$(sconfdir)/roles
	$(MKDIR_P) $(DESTDIR)$(prefixlibdir)
	cp -r roles $(DESTDIR)$(prefixlibdir)

uninstall-config:
	rmdir $(DESTDIR)$(sconfdir)/roles
	rm -f $(DESTDIR)$(prefixlibdir)/roles/*
	rmdir $(DESTDIR)$(prefixlibdir)/roles

install-data-local: $(INSTALL_TARGETS)

uninstall-local: $(UNINSTALL_TARGETS)
