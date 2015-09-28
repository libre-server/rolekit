# -*- coding: utf-8 -*-
#
# Copyright (C) 2014 Red Hat, Inc.
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

import string
import random
import re
from rolekit.errors import *
from rolekit.config import VALIDATE_NAME_REGEXP

"""
Utilities shared by role implementations
"""

def generate_password(size=16, complex=False):
    """
    Generate a random password using either ascii+digits
    or all printable characters.
    """
    if complex:
        password = ''.join(random.choice(string.printable)
                           for _ in range(size))
    else:
        password = ''.join(random.choice(string.ascii_letters + string.digits)
                           for _ in range(size))
    return password

def validate_name(name):
    """
    Check instance name for valid chars. See INSTANCE_NAME_REGEXP in
    rolekit.config.

    Raises INVALID_NAME error if the name is not valid,
    returns True otherwise.
    """
    if not re.match(VALIDATE_NAME_REGEXP, name):
        raise RolekitError(INVALID_NAME, "'%s' is not a valid name." % name)
    return True
