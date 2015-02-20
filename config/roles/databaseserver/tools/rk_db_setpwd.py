#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Red Hat, Inc.
#
# Authors:
# Stephen Gallagher <sgallagh@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import sys
import psycopg2
import argparse

from rolekit.logger import log


def parse_cmdline():
    parser = argparse.ArgumentParser(
                        description=("This function will set a password for "
                                     "an existing role on the server. For "
                                     "security purposes, the password must "
                                     "be provided via STDIN."))
    parser.add_argument('--debug',
                        nargs='?', const=1, default=0, type=int,
                        choices=range(1, log.DEBUG_MAX + 1),
                        help="""Enable logging of debug messages.
                                Additional argument in range 1..%s can be used
                                to specify log level.""" % log.DEBUG_MAX,
                        metavar="level")

    parser.add_argument('--database',
                        nargs='?', type=str,
                        dest="database",
                        help="""The database the user owns.""",
                        required=True)

    parser.add_argument('--user',
                        nargs='?', type=str,
                        dest="user",
                        help="""The user on which to set the password""",
                        required=True)

    return parser.parse_args()


def setup_logging(args):
    # Set up logging capabilities
    log.setDateFormat("%Y-%m-%d %H:%M:%S")
    log.setFormat("%(date)s %(label)s%(message)s")

    if args.debug:
        log.setInfoLogLevel(log.INFO_MAX)
        log.setDebugLogLevel(args.debug)
        log.addInfoLogging("*", log.stdout)
        log.addDebugLogging("*", log.stdout)


def main():
    args = parse_cmdline()

    setup_logging(args)
    log.debug1("Arguments: %s" % sys.argv)

    # Read the password from stdin
    user_pass = raw_input(False)

    # Check for valid database and user names
    # We restrict this to having only letters, numbers
    # and underscores, for safety against SQL injection
    identifier = re.compile(r"^[^\d\W]\w*\Z")

    if not identifier.match(args.user):
        log.error("The user name was not a valid identifier.")
        sys.exit(1)

    # Connect to the local database via 'peer'
    conn = psycopg2.connect(database=args.database)
    log.info1("Connected to local database '%s'" % args.database)
    cur = conn.cursor()


    # Construct the SQL statement
    sql_msg = ("ALTER ROLE %s WITH ENCRYPTED PASSWORD" %
               (args.user) + " %(pwd)s;")
    log.info1("Executing: %s" % sql_msg)
    log.debug10("Password: [%s]", user_pass)

    # Submit the request
    cur.execute(sql_msg, {'pwd': user_pass})

    sys.exit(0)


if __name__ == '__main__':
    main()
