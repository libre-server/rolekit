SUBDIRS = 

dist_bin_SCRIPTS = rolectl
dist_sbin_SCRIPTS = roled

nobase_dist_python_DATA = \
	rolekit/async.py \
	rolekit/client.py \
	rolekit/dbus_utils.py \
	rolekit/errors.py \
	rolekit/functions.py \
	rolekit/logger.py \
	rolekit/__init__.py \
	rolekit/config/dbus.py \
	rolekit/config/__init__.py \
	rolekit/server/dbusrole.py \
	rolekit/server/decorators.py \
	rolekit/server/roled.py \
	rolekit/server/rolebase.py \
	rolekit/server/__init__.py \
	rolekit/server/server.py \
	rolekit/server/io/__init__.py \
	rolekit/server/io/rolesettings.py

EXTRA_DIST = \
	rolekit/config/__init__.py.in

CLEANFILES = *~ *\# .\#* *.py?

install-exec-hook:
	@echo "Fixing python shebang"
	@list='$(dist_bin_SCRIPTS)'; \
	for p in $$list; do \
	  echo $(top_srcdir)/fix_python_shebang.sh "$(DESTDIR)$(bindir)/$$p"; \
	  $(top_srcdir)/fix_python_shebang.sh "$(DESTDIR)$(bindir)/$$p"; \
	done
	@list='$(dist_sbin_SCRIPTS)'; \
	for p in $$list; do \
	  echo $(top_srcdir)/fix_python_shebang.sh "$(DESTDIR)$(sbindir)/$$p"; \
	  $(top_srcdir)/fix_python_shebang.sh "$(DESTDIR)$(sbindir)/$$p"; \
	done
