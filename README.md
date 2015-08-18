README for rolekit
==================

rolekit provides a D-Bus API for roles.

Development:
------------
To check out the source repository, you can use:

  git clone https://github.com/libre-server/rolekit.git

This will create a local copy of the repository.


Working With The Source Repository:
-----------------------------------
You can use the source repository directly to test out changes. Change into the 
rolekit base directory and set the following environment variables.
```
export ROLEKIT_DEVEL_ENV=$(pwd)/src
export PYTHONPATH=$ROLEKIT_DEVEL_ENV
```

Install the following requirements or packages:

* gettext
* intltool
* glib2: /usr/bin/glib-compile-schemas
* glib2-devel: /usr/share/aclocal/gsettings.m4
* systemd-units
* dbus-python
* python-slip-dbus (https://github.com/nphilipp/python-slip)
* python-decorator

To be able to create man pages and documentation from docbook files:

* docbook-style-xsl
* transifex-client

Use
```
  ./autogen.sh
```
in the base directory to create for example src/server/config/__init__.py

Use
```
  make
```
to create the documentation and to update the po files.

Now you are done.

Working With the Vagrant Image:
-------------------------------
For now, the Vagrant image only works with libvirt. The best experience is on
Fedora 22+. Follow the instructions at
http://fedoramagazine.org/running-vagrant-fedora-22/ for initial setup of your
local machine.

Once that is done, the following commands will work to provision and deploy
rolekit into a virtual machine for testing:
```
vagrant up
```
Whenever you make changes to the local sources, you can run
```
vagrant rsync && vagrant provision
```
to have them compiled and deployed automatically onto the target system.

Links:
------
* Homepage:          https://github.com/libre-server/rolekit/
* Git repo browser:  https://github.com/libre-server/rolekit/
* Git repo:          https://github.com/libre-server/rolekit.git
* Documentation:     <pending>


Directory Structure:
--------------------
* config/
 * Configuration files
* config/roles
 * Role definitions
* doc/
 * Documentation
* doc/man/
 * Base directory for man pages
* doc/man/man1/
 * Man(1) pages
* po/
 * Translations
* shell-completion/
 * Base directory for auto completion scripts
* shell-completion/bash/
 * Bash auto completion scripts
* src/
 * Source tree
* src/server/
 * Import tree for the service and all applications
* src/tests/
 * Test scripts
