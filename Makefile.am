SUBDIRS = config doc po src

DISTCHECK_CONFIGURE_FLAGS = --with-system-bus-services-dir="$$dc_install_base"/$(datadir)//dbus-1/system-services

TESTS = tests/async_test.py
TEST_EXTENSIONS = .py
PY_LOG_COMPILER = python
AM_TESTS_ENVIRONMENT = export PYTHONPATH=$(abs_top_srcdir)/src;

EXTRA_DIST = \
	COPYING \
	README \
	autogen.sh \
	${PACKAGE_NAME}.spec \
	fix_python_shebang.sh \
	$(TESTS)

CLEANFILES = *~ *\# .\#* *.tar*

DISTCLEANFILES = config.log intltool-*

DISTCLEANDIRS = autom4te.cache ${PACKAGE_NAME}-*

all: report

tag:
	@spec_ver=`awk '/Version:/ { print $$2}' ${PACKAGE_NAME}.spec`; \
	if test "$$spec_ver" != "${PACKAGE_VERSION}"; then \
		echo "Spec file and package versions differ: $$spec_ver != ${PACKAGE_VERSION}"; \
		secs=10; \
		echo -n "Using ./autogen.sh in $$secs seconds: "; \
		for i in `seq $$secs -1 1`; do echo -n "."; sleep 1; done; echo; \
		./autogen.sh; \
		echo; \
		echo "Please run make again to apply version changes."; \
		exit 1; \
	fi
	@if ! git diff --quiet --exit-code; then \
		clear; \
		echo -n "========================================"; \
		echo "========================================"; \
		PAGER= git diff; \
		echo -n "========================================"; \
		echo "========================================"; \
		echo "Do you want to commit these changes? (y/N)"; \
		read answer; \
		[ "$$answer" == "Y" -o "$$answer" == "y" ] || exit 1; \
		git commit -a -m "$(PACKAGE_TAG)"; \
	fi
	git tag -f $(PACKAGE_TAG)
	git push --all
	git push --tags

#dist: clean-docs update-docs tx-pull
dist: clean-docs update-docs

update-docs:
	make -C doc/xml

clean-docs:
	make -C doc/xml clean

tx-pull:
	tx pull

tx-push:
	tx push -s

#archive: update-po tx-push $(desktop_DATA) tag dist
archive: update-po $(desktop_DATA) tag dist
	scp "${PACKAGE_NAME}-$(PACKAGE_VERSION).tar.bz2" fedorahosted.org:${PACKAGE_NAME}
	@echo "The archive is in ${PACKAGE_NAME}-$(PACKAGE_VERSION).tar.bz2"
	@echo "Also have a look at https://fedorahosted.org/released/${PACKAGE_NAME}/"

local: distclean
	@rm -rf ${PACKAGE_NAME}-$(PACKAGE_VERSION).tar.bz2
	@rm -rf /tmp/${PACKAGE_NAME}-$(PACKAGE_VERSION) /tmp/${PACKAGE_NAME}
	@dir=$$PWD; cd /tmp; cp -a $$dir ${PACKAGE_NAME}
	@mv /tmp/${PACKAGE_NAME} /tmp/${PACKAGE_NAME}-$(PACKAGE_VERSION)
	@dir=$$PWD; cd /tmp; tar --bzip2 -cSpf $$dir/${PACKAGE_NAME}-$(PACKAGE_VERSION).tar.bz2 ${PACKAGE_NAME}-$(PACKAGE_VERSION)
	@rm -rf /tmp/${PACKAGE_NAME}-$(PACKAGE_VERSION)	
	@echo "The archive is in ${PACKAGE_NAME}-$(PACKAGE_VERSION).tar.bz2"

test-rpm: dist
	@rpmbuild -ta $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar.bz2

test-srpm: dist
	@rpmbuild -ts $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar.bz2

update-po-files:
	find $(top_srcdir)/src/ \( -name "*.py" -or -executable -not -type d \) -print | sort > $(top_srcdir)/po/POTFILES.in

update-po:
	ls $(top_srcdir)/po/*.po | sed 's/.*\/po\///;s/.po//' > $(top_srcdir)/po/LINGUAS
	make -C po update-po ${PACKAGE_NAME}.pot

clean-po:
	@for cat in `cat ${top_srcdir}/po/LINGUAS`; do \
		msgattrib --translated --no-fuzzy --no-obsolete --force-po --no-location --clear-previous --strict $(top_srcdir)/po/$$cat.po -o $(top_srcdir)/po/$$cat.out; \
		mv -f $(top_srcdir)/po/$$cat.out $(top_srcdir)/po/$$cat.po; \
	done

report:
	@for cat in `cat ${top_srcdir}/po/LINGUAS`; do \
		echo -n "$$cat: "; \
		$(MSGFMT) --statistics -o /dev/null $(top_srcdir)/po/$$cat.po; \
	done

distclean-local:
	-test -z "$(DISTCLEANDIRS)" || rm -rf $(DISTCLEANDIRS)
