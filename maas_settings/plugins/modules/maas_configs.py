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


def config_needs_updating(current, wanted, module):
    """
    Compare two config definitions and see if there are differences
    in the fields we allow to be changed
    """

    ret = False

    current_filtered = {k: v for k, v in current.items() if k in CONFIG_MODIFY_KEYS}
    wanted_filtered = {k: v for k, v in wanted.items() if k in CONFIG_MODIFY_KEYS}

    if sorted(current_filtered) != sorted(wanted_filtered):
        ret = True

    for key in wanted_filtered.keys():
        if str(wanted_filtered[key]) != str(current_filtered[key]):
            ret = True

    return ret


def get_maas_configs(session, module):
    """
    Grab the current list of configs
    """
    try:
        filtered_configs = []
        current_configs = session.get(f"{module.params['site']}/api/2.0/configs/")
        current_configs.raise_for_status()

        # filter the list down to keys we support
        for config in current_configs.json():
            filtered_configs.append(
                {k: v for k, v in config.items() if k in CONFIG_SUPPORTED_KEYS}
            )
        return filtered_configs
    except exceptions.RequestException as e:
        module.fail_json(msg="Failed to get current config list: {}".format(str(e)))


def lookup_config(lookup, current_configs, module):
    """
    Given a lookup return a config if the lookup
    matches a current config
    """

    if lookup["name"] in current_configs.keys():
        return current_configs[lookup["name"]]

    return None


def maas_update_configs(session, current_configs, module_configs, module, res):
    """
    Given a list of configs to add, we add those that don't exist
    If they exist, we check if something has changed and if it
    is a parameter that we can update, we call a function to do
    that.
    """
    configlist_added = []
    configlist_updated = []

    for config in module_configs:
        if (matching_config := lookup_config(config, current_configs, module)) is None:
            configlist_added.append(config)
            res["changed"] = True

            if not module.check_mode:
                payload = {
                    "name": config["name"],
                    "comment": config["comment"] if "comment" in config.keys() else "",
                    "definition": (
                        config["definition"] if "definition" in config.keys() else ""
                    ),
                    "kernel_opts": (
                        config["kernel_opts"] if "kernel_opts" in config.keys() else ""
                    ),
                }
                try:
                    r = session.post(
                        f"{module.params['site']}/api/2.0/configs/",
                        data=payload,
                    )
                    r.raise_for_status()
                except exceptions.RequestException as e:
                    module.fail_json(
                        msg=f"config Add Failed: {format(str(e))} with payload {format(payload)} and {format(config)}"
                    )
        else:
            if config_needs_updating(matching_config, config, module):
                configlist_updated.append(config)
                res["changed"] = True

                if not module.check_mode:
                    payload = {
                        "comment": (
                            config["comment"] if "comment" in config.keys() else ""
                        ),
                        "definition": (
                            config["definition"]
                            if "definition" in config.keys()
                            else ""
                        ),
                        "kernel_opts": (
                            config["kernel_opts"]
                            if "kernel_opts" in config.keys()
                            else ""
                        ),
                    }
                    try:
                        r = session.put(
                            f"{module.params['site']}/api/2.0/configs/{config['name']}/",
                            data=payload,
                        )
                        r.raise_for_status()
                    except exceptions.RequestException as e:
                        module.fail_json(
                            msg=f"config Update Failed: {format(str(e))} with payload {format(payload)} and {format(config)}"
                        )

    new_configs_dict = {
        item["name"]: item for item in get_maas_configs(session, module)
    }

    res["diff"] = dict(
        before=safe_dump(current_configs),
        after=safe_dump(new_configs_dict),
    )

    if configlist_added:
        res["message"].append("Added configs: " + str(configlist_added))

    if configlist_updated:
        res["message"].append("Updated configs: " + str(configlist_updated))


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

    validate_module_parameters(module)

    response = grab_maas_apikey(module)
    api_cred = maas_api_cred(response.json())

    maas_session = OAuth1Session(
        api_cred.client_key,
        resource_owner_key=api_cred.resource_owner_key,
        resource_owner_secret=api_cred.resource_owner_secret,
        signature_method="PLAINTEXT",
    )

    current_configs_dict = {
        item["name"]: item for item in get_maas_configs(maas_session, module)
    }

    if module.params["state"] == "present":
        maas_add_configs(
            maas_session,
            current_configs_dict,
            module.params["configs"],
            module,
            result,
        )

    elif module.params["state"] == "absent":
        maas_delete_configs(
            maas_session,
            current_configs_dict,
            module.params["configs"],
            module,
            result,
        )

    elif module.params["state"] == "exact":
        if module.params["configs"]:
            maas_exact_configs(
                maas_session,
                current_configs_dict,
                module.params["configs"],
                module,
                result,
            )
        configs = module.params["configs"]
    for config in configs:
        if any(c in config["name"] for c in string.whitespace):
            module.fail_json(
                msg=f"config names can not contain whitespace, found {config}"
            )


def main():
    run_module()


if __name__ == "__main__":
    main()
