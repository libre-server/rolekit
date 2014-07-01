SUBDIRS = 

dist_bin_SCRIPTS = rolectl
dist_sbin_SCRIPTS = rolekitd

nobase_dist_python_DATA = \
	rolekit/client.py \
	rolekit/dbus_utils.py \
	rolekit/errors.py \
	rolekit/functions.py \
	rolekit/__init__.py \
	rolekit/config/dbus.py \
	rolekit/config/__init__.py \
	rolekit/server/decorators.py \
	rolekit/server/rolekitd.py \
	rolekit/server/__init__.py \
	rolekit/server/server.py \
	rolekit/server/io/__init__.py

EXTRA_DIST = \
	rolekit/config/__init__.py.in

CLEANFILES = *~ *\# .\#* *.py?

install-data-local:
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
