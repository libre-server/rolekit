README for rolekit
==================

rolekit provides a D-Bus API for roles.

Installation:
=============

Fedora 21:
----------
```
yum install rolekit
```

Fedora 22+:
-----------
```
dnf install rolekit
```
Other Linux Systems:
--------------------
Not yet supported


Deploying Roles
===============
The rolekit service provides a D-BUS API for deploying server roles onto the system. This API is accessible only to processes running as the `root` user on the system.

To deploy a role with the `rolectl` command-line tool, you would do (as root):
```
rolectl deploy <role_type> --name=<instance_name> [--settings-file=<path>|--settings-stdin]
```
For example, to deploy a Domain Controller on the local system:
```
rolectl deploy domaincontroller --name=mycompany.com
```

Most roles are installable with no additional setting (selecting reasonable defaults and generating passwords automatically where necessary). For roles (like `domaincontroller` where passwords are generated, they can be retrieved with:
```
rolectl settings <role_type>/<instance_name>
```
Using the example above:
```
rolectl settings domaincontroller/mycompany.com
```

Once sensitive information like generated passwords has been retrieved, they should be purged from the system using
```
rolectl sanitize <role_type>/<instance_name>
```

If the system no longer needs to have this role, it can be decommissioned with
```
rolectl decommission <role_type>/<instance_name>
```

If you wish to deploy a role with one or more custom configuration options (instead of the defaults offered by the role), you will need to provide those settings to `rolectl` using a JSON settings-file using the `--settings-file` option (or feeding the JSON directly into stdin with `--settings-stdin`).

A real-world example: Deploy a domain controller with no DNS server and a manually-selected administrator password. We will create a JSON file named `dc.json` as follows:
```
{
    "serve_dns": false,
    "admin_password": "MySecretPasswordDon'tTellAnyone"
}
```
To install the domain controller with this settings file, do:
```
rolectl deploy domaincontroller --name=mycompany.org --settings-file=./dc.json
```

All options for the available roles can be found in their manual pages: rolekit.roles.<role_type>(5)

Development
===========
To check out the source repository, you can use:

  git clone https://github.com/libre-server/rolekit.git

This will create a local copy of the repository.


Working With The Source Repository
----------------------------------
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

Working With the Vagrant Image
------------------------------
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

Links
-----
* Homepage:          https://github.com/libre-server/rolekit/
* Git repo browser:  https://github.com/libre-server/rolekit/
* Git repo:          https://github.com/libre-server/rolekit.git
* Documentation:     <pending>


Directory Structure
-------------------
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
