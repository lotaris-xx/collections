# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Red Hat | Ansible
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Options for specifying auth information

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    DOCUMENTATION = r"""
options:
    password:
        description: Password for username used to get API token. Mutually excludive with O(token).
        required: true
        type: str
    site:
        description: URL of the MAAS site (generally ending in /MAAS)
        required: true
        type: str
    username:
        description: Username to get API token. Mutually exclusive with O(token).
        required: true
        type: str
    token:
        description: API Token, a string in 3 parts separated by ':'. Mutually exclusive with O(username)/O(password).
        required: true
        type: string
"""
