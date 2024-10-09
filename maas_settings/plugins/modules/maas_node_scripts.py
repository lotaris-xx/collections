#!/usr/bin/python

from __future__ import absolute_import, division, print_function
from ansible.module_utils.basic import missing_required_lib

from yaml import safe_dump

try:
    from requests import exceptions

    HAS_REQUESTS = True
except:
    HAS_REQUESTS = False

try:
    from requests_oauthlib import OAuth1Session

    HAS_REQUESTS_OAUTHLIB = True
except:
    HAS_REQUESTS_OAUTHLIB = False

NODE_SCRIPT_SUPPORTED_KEYS = ["name"]
NODE_SCRIPT_MODIFY_KEYS = []

__metaclass__ = type

DOCUMENTATION = r"""
---
module: maas_node_scripts

short_description: Configure MAAS node scripts

version_added: "1.0.0"

description: Configure MAAS node scripts

options:
    state:
        description:
          - if C(absent) then the node script(s) will be removed if currently present.
          - if C(present) then the node script(s) will be created/updated.
          - if C(exact) then the resulting node script list will match what is passed in.
        required: false
        type: str
        default: present
        choices: [ absent, present, exact ]
    scripts_dir:
        description: Directory where node scripts are located
        required: true
        type: str
    user_scripts:
        description: A list containing node script specifier dictionaries
        required: true
        type: list
        suboptions:
          name:
              description: The name of the node script
              required: true
              type: str
          file:
              description: The location of the node script
              required: true
              type: str

extends_documentation_fragment:
    - rhc.maas_settings.maas_auth_options

notes:
   - The API accepts more options for O(node_scripts) list members
     however only those mentioned are supported by this
     module.

requirements:
   - requests
   - requests-oauthlib

author:
    - Allen Smith (@asmith-tmo)
"""

EXAMPLES = r"""
# Add 2 node_scripts if they don't exist
-  username: user
   password: password
   script_dir: /root/user_scripts
   node_scripts:
     - name: "script1"
       file: "script1.sh"
     - name: "check health"
       file: "0-check_health.sh"

# Remove two node_scripts if they exist
-  username: user
   password: password
   state: absent
   node_scripts:
     - name: script1
     - name: check health

# Add/Remove as needed to exactly match given list
-  token: api_token
   state: exact
   node_scripts:
     - name: validate app perms
       file: validate_app_perms.sh
     - name: script2.sh
       file: script2.sh

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


def lookup_node_script(lookup, current_scripts, module):
    """
    Given a lookup return a script if the lookup
    matches a current script
    """
    if lookup["name"] in current_scripts.keys():
        return current_scripts[lookup["name"]]

    return None


def node_script_needs_updating(current, wanted, module, session):
    """
    Compare two node_script definitions and see if there are differences
    in the fields we allow to be changed
    """
    ret = False
    # Special handling for the contents of the script
    try:
        payload = {"op": "download", "name": wanted["name"]}
        current_content = session.get(
            f"{module.params['site']}/api/2.0/scripts/{wanted['name']}", params=payload
        )
        current_content.raise_for_status()

    except exceptions.RequestException as e:
        module.fail_json(
            msg="Failed to get current node_script list: {}".format(str(e))
        )

    if wanted["contents"] != current_content.text:
        ret = True

    # Handle any other keys we may want to support in the future
    current_filtered = {
        k: v for k, v in current.items() if k in NODE_SCRIPT_MODIFY_KEYS
    }
    wanted_filtered = {k: v for k, v in wanted.items() if k in NODE_SCRIPT_MODIFY_KEYS}

    for key in wanted_filtered.keys():
        if (key not in current_filtered.keys()) or (
            str(wanted_filtered[key]) != str(current_filtered[key])
        ):
            ret = True

    return ret


def get_maas_node_scripts(session, module):
    """
    Grab the current list of node_scripts
    """
    try:
        filtered_node_scripts = []
        current_node_scripts = session.get(f"{module.params['site']}/api/2.0/scripts/")
        current_node_scripts.raise_for_status()

        # filter the list down to keys we support
        for node_script in current_node_scripts.json():
            # Ignore the scripts shipped with MAAS
            if not node_script["default"]:
                filtered_node_scripts.append(
                    {
                        k: v
                        for k, v in node_script.items()
                        if k in NODE_SCRIPT_SUPPORTED_KEYS
                    }
                )
        return filtered_node_scripts
    except exceptions.RequestException as e:
        module.fail_json(
            msg="Failed to get current node_script list: {}".format(str(e))
        )


def maas_add_node_scripts(
    session, current_node_scripts, module_node_scripts, module, res
):
    """
    Given a list of node_scripts to add, we add those that don't exist
    If they exist, we check if the script has changed and if it has we
    upload the new script.
    """
    script_list_added = []
    script_list_updated = []

    for script in module_node_scripts:
        if (
            matching_script := lookup_node_script(script, current_node_scripts, module)
        ) is None:
            script_list_added.append(script["name"])
            res["changed"] = True

            if not module.check_mode:
                try:
                    r = session.post(
                        f"{module.params['site']}/api/2.0/scripts/",
                        files={script["name"]: (script["name"], script["contents"])},
                    )
                    r.raise_for_status()
                except exceptions.RequestException as e:
                    module.fail_json(
                        msg=f"Node Script Add Failed: {format(str(e))} with {r.text} and {format(script)}"
                    )
        else:
            if node_script_needs_updating(matching_script, script, module, session):
                script_list_updated.append(script["name"])
                res["changed"] = True

                if not module.check_mode:
                    try:
                        r = session.put(
                            f"{module.params['site']}/api/2.0/scripts/{script['name']}",
                            files={
                                script["name"]: (script["name"], script["contents"])
                            },
                        )
                        r.raise_for_status()
                    except exceptions.RequestException as e:
                        module.fail_json(
                            msg=f"script Update Failed: {format(str(e))} with {r.text} and {format(script)}"
                        )

    new_node_scripts_dict = {
        item["name"]: item for item in get_maas_node_scripts(session, module)
    }

    if script_list_added:
        res["message"].append("Added node_scripts: " + str(script_list_added))

    if script_list_updated:
        res["message"].append("Updated node_scripts: " + str(script_list_updated))
        for script_name in script_list_updated:
            del current_node_scripts[script_name]
            new_node_scripts_dict[script_name]["name"] += " (modified)"

    res["diff"] = dict(
        before=safe_dump(current_node_scripts),
        after=safe_dump(new_node_scripts_dict),
    )


def maas_delete_all_node_scripts(session, current_node_scripts, module, res):
    """
    Delete all node_scripts
    """
    scriptlist = []

    for item in current_node_scripts:
        node_script = current_node_scripts[item]
        scriptlist.append(item)
        res["changed"] = True

        if not module.check_mode:
            payload = {
                "name": node_script["name"],
            }
            try:
                r = session.delete(
                    f"{module.params['site']}/api/2.0/scripts/{node_script['name']}",
                    data=payload,
                )
                r.raise_for_status()
            except exceptions.RequestException as e:
                module.fail_json(
                    msg=f"node_script Remove Failed: {format(str(e))}, {r.text} with {format(current_node_scripts)}"
                )

            new_node_scripts_dict = {
                item["name"]: item for item in get_maas_node_scripts(session, module)
            }

            res["diff"] = dict(
                before=safe_dump(current_node_scripts),
                after=safe_dump(new_node_scripts_dict),
            )

    if scriptlist:
        res["message"].append("Removed node_scripts: " + str(scriptlist))


def maas_delete_node_scripts(
    session, current_node_scripts, module_node_scripts, module, res
):
    """
    Given a list of node_scripts to remove, we delete those that exist"
    """
    script_list = []

    for node_script in module_node_scripts:
        if node_script["name"] in current_node_scripts.keys():
            script_list.append(node_script)
            res["changed"] = True

            if not module.check_mode:
                try:
                    r = session.delete(
                        f"{module.params['site']}/api/2.0/scripts/{node_script['name']}",
                    )
                    r.raise_for_status()
                except exceptions.RequestException as e:
                    module.fail_json(
                        msg=f"node_script Remove Failed: {format(str(e))}, {r.text} with {format(current_node_scripts)}"
                    )

                new_node_scripts_dict = {
                    item["name"]: item
                    for item in get_maas_node_scripts(session, module)
                }

                res["diff"] = dict(
                    before=safe_dump(current_node_scripts),
                    after=safe_dump(new_node_scripts_dict),
                )

    if script_list:
        res["message"].append("Removed node_scripts: " + str(script_list))


def maas_exact_node_scripts(
    session, current_node_scripts, module_node_scripts, module, res
):
    """
    Given a list of node_scripts, remove and add/update as needed
    to make reality match the list
    """
    wanted = []
    wanted_add = []
    wanted_delete = []
    wanted_update = []

    for node_script in module_node_scripts:
        wanted.append(node_script["name"])

    module_node_scripts_dict = {k["name"]: k for k in module_node_scripts}
    delete_list = [
        script_name
        for script_name in current_node_scripts.keys()
        if script_name not in wanted
    ]
    add_list = [
        script_name
        for script_name in wanted
        if script_name not in current_node_scripts.keys()
    ]
    update_list = [
        script_name
        for script_name in wanted
        if script_name in current_node_scripts.keys()
    ]

    if delete_list:
        wanted_delete = [{"name": k} for k in delete_list]
        maas_delete_node_scripts(
            session, current_node_scripts, wanted_delete, module, res
        )

    if add_list:
        wanted_add = [module_node_scripts_dict[k] for k in add_list]
        maas_add_node_scripts(session, current_node_scripts, wanted_add, module, res)

    if update_list:
        wanted_update = [module_node_scripts_dict[k] for k in update_list]
        maas_add_node_scripts(session, current_node_scripts, wanted_update, module, res)


def run_module():
    module_args = dict(
        script_dir=dict(type="str", required=True),
        user_scripts=dict(type="list", required=True),
        password=dict(type="str", no_log=True),
        token=dict(type="str", no_log=True),
        username=dict(type="str"),
        site=dict(type="str", required=True),
        state=dict(type="str", required=False, default="present"),
    )

    result = dict(changed=False, message=[], diff={})

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_together=[["username", "password"]],
        required_one_of=[["username", "token"], ["password", "token"]],
        mutually_exclusive=[["username", "token"], ["password", "token"]],
    )

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

    validate_module_parameters(module)

    current_node_scripts_dict = {
        item["name"]: item for item in get_maas_node_scripts(maas_session, module)
    }

    if module.params["state"] == "present":
        maas_add_node_scripts(
            maas_session,
            current_node_scripts_dict,
            module.params["user_scripts"],
            module,
            result,
        )

    elif module.params["state"] == "absent":
        maas_delete_node_scripts(
            maas_session,
            current_node_scripts_dict,
            module.params["user_scripts"],
            module,
            result,
        )

    elif module.params["state"] == "exact":
        if module.params["user_scripts"]:
            maas_exact_node_scripts(
                maas_session,
                current_node_scripts_dict,
                module.params["user_scripts"],
                module,
                result,
            )
        else:
            maas_delete_all_node_scripts(
                maas_session,
                current_node_scripts_dict,
                module,
                result,
            )

    module.exit_json(**result)


def validate_module_parameters(module):
    """
    Perform simple validations on module parameters
    """
    import string

    if "user_scripts" in module.params:
        node_scripts = module.params["user_scripts"]

        for script in node_scripts:
            if any(c in script["name"] for c in string.whitespace):
                module.fail_json(
                    msg=f"Script names can not contain whitespace, found '{script['name']}'"
                )


def main():
    run_module()


if __name__ == "__main__":
    main()
