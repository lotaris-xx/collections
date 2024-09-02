#!/usr/bin/python

from __future__ import absolute_import, division, print_function
from ansible.module_utils.basic import missing_required_lib

from collections import Counter
from yaml import safe_dump

try:
    from requests import post, exceptions

    HAS_REQUESTS = True
except:
    HAS_REQUESTS = False

try:
    from requests_oauthlib import OAuth1Session

    HAS_REQUESTS_OAUTHLIB = True
except:
    HAS_REQUESTS_OAUTHLIB = False

__metaclass__ = type

DOCUMENTATION = r"""
---
module: maas_configs

short_description: Set MAAS configs

version_added: "1.0.0"

description: Given a dictionary of MAAS config settings, this module will compare each value to the
             current setting and update as needed.

options:
    password:
        description: Password for username used to get API token
        required: true
        type: str
    site:
        description: URL of the MAAS site (generally ending in /MAAS)
        required: true
        type: str
    username:
        description: Username to get API token for
        required: true
        type: str
    configs:
        description: A dictionary containing config settings
        required: true
        type: dict

notes:
    - The configs are always defined on the server, even if an empty value
    - It isn't possible to get a list of all keys available, so must look at MAAS server or MAAS API docs for valid values.

requirements:
   - requests
   - requests-oauthlib

author:
    - Allen Smith (@asmith-tmo)
"""

EXAMPLES = r"""
# Add/Remove as needed to exactly match given dictionary
-  maas_configs:
     username: user
     password: password
     configs:
       network_discovery: "disabled"
"""

RETURN = r"""
message:
    description: Status messages
    type: list
    returned: always
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.rhc.maas_settings.plugins.module_utils.maas_common import (
    maas_api_cred,
    grab_maas_apikey,
)


def lookup_config(session, lookup, module):
    """
    Given a lookup return the current config if the lookup succeds
    """
    try:

        payload = {"name": lookup}
        current_config = session.get(
            f"{module.params['site']}/api/2.0/maas/op-get_config", params=payload
        )

        current_config.raise_for_status()

        return current_config.json()

    except exceptions.RequestException as e:
        module.fail_json(
            msg="Failed to get current config for {}: {}".format(lookup, str(e))
        )


def maas_update_config(session, setting, module):
    """
    Update a given config
    """
    res["changed"] = True

    if not module.check_mode:
        payload = {
            "name": setting.key(),
            "value": setting.value(),
        }
        try:
            r = session.put(
                f"{module.params['site']}/api/2.0/maas/maas/op-set_config",
                data=payload,
            )
            r.raise_for_status()
        except exceptions.RequestException as e:
            module.fail_json(
                msg=f"config Update Failed: {format(str(e))} with payload {format(payload)} and {format(setting)}"
            )

    res["message"].append("Updated config: " + str(configlist_updated))


def run_module():
    module_args = dict(
        configs=dict(type="dict", required=True),
        password=dict(type="str", required=True, no_log=True),
        username=dict(type="str", required=True),
        site=dict(type="str", required=True),
    )

    result = dict(changed=False, message=[], diff={})

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib("requests"))

    if not HAS_REQUESTS_OAUTHLIB:
        module.fail_json(msg=missing_required_lib("requests_oauthlib"))

    response = grab_maas_apikey(module)
    api_cred = maas_api_cred(response.json())

    maas_session = OAuth1Session(
        api_cred.client_key,
        resource_owner_key=api_cred.resource_owner_key,
        resource_owner_secret=api_cred.resource_owner_secret,
        signature_method="PLAINTEXT",
    )

    configs = module.params["configs"]

    current_configs = {}
    # For each config setting
    for setting in configs:
        matching_setting = lookup_config(maas_session, setting, module)
        current_configs.update(matching_setting)

        # If the setting needs to be updated
        if configs[setting] != matching_setting.value():
            # Update the setting
            maas_update_config(
                maas_session,
                setting,
                module,
            )

    result["diff"] = dict(
        before=safe_dump(current_configs),
        after=safe_dump(configs),
    )


def main():
    run_module()


if __name__ == "__main__":
    main()
