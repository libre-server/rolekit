#!/bin/bash

sed -e "s@^#\!/usr/bin/python3\$@#\!/usr/bin/python3 -Es@" -i $@
