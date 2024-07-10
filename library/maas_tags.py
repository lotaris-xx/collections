#!/usr/bin/python

# Copyright: Allen Smith <asmith687@t-mobile.com>
# License: MIT-0 (See https://opensource.org/license/mit-0)
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

TAG_SUPPORTED_KEYS = ["name", "comment", "definition", "kernel_opts"]
TAG_MODIFY_KEYS = ["comment", "definition", "kernel_opts"]

__metaclass__ = type

DOCUMENTATION = r"""
---
module: maas_tags

short_description: Configure MAAS tags

version_added: "1.0.0"

description: Configure MAAS tags

options:
    password:
        description: Password for username used to get API token
        required: true
        type: str
    site:
        description: URL of the MAAS site (generally ending in /MAAS)
        required: true
        type: str
    state:
        description:
          - if C(absent) then the static_route(s) will be removed if currently present.
          - if C(present) then the static_route(s) will be created/updated.
          - if C(exact) then the resulting static_route list will match what is passed in.
        required: false
        type: str
        default: present
        choices: [ absent, present, exact ]
    username:
        description: Username to get API token for
        required: true
        type: str
    tags:
        description: A list containing tag specifier dictionaries
        required: true
        type: list
        suboptions:
          name:
              description: The name of the tag (used in URLs, so should be short and follow rules for components of a URL)
              required: true
              type: str
          comment:
              description: A description of what the the tag will be used for in natural language
              required: false
              type: str
          definition:
              description: An XPATH query that is evaluated against the hardware_details stored for all nodes (i.e. the output of lshw -xml).
              required: false
              type: str
          kernel_opts:
              description: Nodes associated with this tag will add this string to their kernel options when booting.
                           The value overrides the global kernel_opts setting. If more than one tag is associated with a node,
                           command line will be concatenated from all associated tags, in alphabetic tag name order.
              required: false
              type: int

notes:
    - Source puppet facts use only names, so that code is most tested.

requirements:
   - requests
   - requests-oauthlib

author:
    - Allen Smith (@asmith-tmo)
"""

EXAMPLES = r"""
# Add/Remove as needed to exactly match given list
-  maas_tags:
     username: user
     password: password
     state: exact
     tags:
       - name: first_tag
       - name: another_tag
"""

RETURN = r"""
message:
    description: Status messages
    type: list
    returned: always
"""

from ansible.module_utils.basic import AnsibleModule


class maas_api_cred:
    """
    Represents a MAAS API Credenital
    Provides both MAAS API and OAuth terminology
    """

    def __init__(self, api_json):
        self.consumer_key = api_json["consumer_key"]
        self.token_key = api_json["token_key"]
        self.token_secret = api_json["token_secret"]

        self.client_key = self.consumer_key
        self.resource_owner_key = self.token_key
        self.resource_owner_secret = self.token_secret


def static_route_needs_updating(current, wanted, module):
    """
    Compare two static_route definitions and see if there are differences
    in the fields we allow to be changed
    """

    ret = False
    current_filtered = {k: v for k, v in current.items() if k in TAG_MODIFY_KEYS}
    wanted_filtered = {k: v for k, v in wanted.items() if k in TAG_MODIFY_KEYS}

    # We need to compare manually as source may match name or cidr attributes
    if "metric" in wanted_filtered.keys():
        if str(wanted_filtered["metric"]) != str(current_filtered["metric"]):
            ret = True

    if wanted_filtered["gateway_ip"] != current_filtered["gateway_ip"]:
        ret = True

    if wanted_filtered["source"] not in (
        current_filtered["source"]["name"],
        current_filtered["source"]["cidr"],
    ):
        ret = True

    return ret


def get_maas_tags(session, module):
    """
    Grab the current list of tags
    """
    try:
        filtered_tags = []
        current_tags = session.get(f"{module.params['site']}/api/2.0/static-routes/")
        current_tags.raise_for_status()

        # filter the list down to keys we support
        for static_route in current_tags.json():
            filtered_tags.append(
                {k: v for k, v in static_route.items() if k in TAG_SUPPORTED_KEYS}
            )
        return filtered_tags
    except exceptions.RequestException as e:
        module.fail_json(
            msg="Failed to get current static_route list: {}".format(str(e))
        )


def grab_maas_apikey(module):
    """
    Connect to MAAS API and grab the 3 part API key
    """
    consumer = "ansible@host"
    uri = "/accounts/authenticate/"
    site = module.params["site"]
    username = module.params["username"]
    password = module.params["password"]

    payload = {
        "username": username,
        "password": password,
        "consumer": consumer,
    }
    try:
        r = post(site + uri, data=payload)
        r.raise_for_status()
        return r
    except exceptions.RequestException as e:
        module.fail_json(msg="Auth failed: {}".format(str(e)))


def lookup_static_route(lookup, current_sroutes, module):
    """
    Given a lookup return a static route if the lookup
    matches either the name or cidr property of a current route
    """

    for item in current_sroutes:
        if lookup in [
            current_sroutes[item]["destination"]["name"],
            current_sroutes[item]["destination"]["cidr"],
        ]:
            return current_sroutes[item]

    return None


def maas_add_tags(session, current_tags, module_tags, module, res):
    """
    Given a list of tags to add, we add those that don't exist
    If they exist, we check if something has changed and if it
    is a parameter that we can update, we call a function to do
    that.
    """
    sroutelist_added = []
    sroutelist_updated = []
    matching_route = {}

    for static_route in module_tags:
        if "metric" not in static_route.keys():
            static_route["metric"] = 0

        if (
            matching_route := lookup_static_route(
                static_route["destination"], current_tags, module
            )
        ) is None:

            sroutelist_added.append(static_route["destination"])
            res["changed"] = True

            if not module.check_mode:
                payload = {
                    "source": static_route["source"],
                    "destination": static_route["destination"],
                    "gateway_ip": static_route["gateway_ip"],
                    "metric": static_route["metric"],
                }
                try:
                    r = session.post(
                        f"{module.params['site']}/api/2.0/static-routes/",
                        data=payload,
                    )
                    r.raise_for_status()
                except exceptions.RequestException as e:
                    module.fail_json(
                        msg=f"static_route Add Failed: {format(str(e))} with payload {format(payload)} and {format(static_route)}"
                    )
        else:
            if static_route_needs_updating(matching_route, static_route, module):
                sroutelist_updated.append(static_route["destination"])
                res["changed"] = True

                static_route["id"] = matching_route["id"]

                if not module.check_mode:
                    payload = {
                        "source": static_route["source"],
                        "gateway_ip": static_route["gateway_ip"],
                        "metric": static_route["metric"],
                    }
                    try:
                        r = session.put(
                            f"{module.params['site']}/api/2.0/static-routes/{static_route['id']}/",
                            data=payload,
                        )
                        r.raise_for_status()
                    except exceptions.RequestException as e:
                        module.fail_json(
                            msg=f"static_route Update Failed: {format(str(e))} with payload {format(payload)} and {format(static_route)}"
                        )

    new_tags_dict = {
        item["destination"]["name"]: item for item in get_maas_tags(session, module)
    }

    res["diff"] = dict(
        before=safe_dump(current_tags),
        after=safe_dump(new_tags_dict),
    )

    if sroutelist_added:
        res["message"].append("Added tags: " + str(sroutelist_added))

    if sroutelist_updated:
        res["message"].append("Updated tags: " + str(sroutelist_updated))


def maas_delete_all_tags(session, current_tags, module, res):
    """
    Delete all static routes
    """
    sroutelist = []

    for item in current_tags:
        sroute = current_tags[item]
        sroutelist.append(sroute["destination"])
        res["changed"] = True

        if not module.check_mode:
            try:
                r = session.delete(
                    f"{module.params['site']}/api/2.0/static-routes/{sroute['id']}/",
                )
                r.raise_for_status()
            except exceptions.RequestException as e:
                module.fail_json(
                    msg=f"static_route Remove Failed: {format(str(e))} with {format(current_tags)}"
                )

            new_tags_dict = {
                item["destination"]["name"]: item
                for item in get_maas_tags(session, module)
            }

            res["diff"] = dict(
                before=safe_dump(current_tags),
                after=safe_dump(new_tags_dict),
            )

    if sroutelist:
        res["message"].append("Removed tags: " + str(sroutelist))


def maas_delete_tags(session, current_tags, module_tags, module, res):
    """
    Given a list of tags to remove, we delete those that exist"
    """
    sroutelist = []

    for sroute in module_tags:
        if (
            matching_route := lookup_static_route(
                sroute["destination"], current_tags, module
            )
        ) is not None:
            sroutelist.append(sroute["destination"])
            res["changed"] = True
            sroute["id"] = matching_route["id"]

            if not module.check_mode:
                try:
                    r = session.delete(
                        f"{module.params['site']}/api/2.0/static-routes/{sroute['id']}/",
                    )
                    r.raise_for_status()
                except exceptions.RequestException as e:
                    module.fail_json(
                        msg=f"static_route Remove Failed: {format(str(e))} with {format(current_tags)}"
                    )

                new_tags_dict = {
                    item["destination"]["name"]: item
                    for item in get_maas_tags(session, module)
                }

                res["diff"] = dict(
                    before=safe_dump(current_tags),
                    after=safe_dump(new_tags_dict),
                )

    if sroutelist:
        res["message"].append("Removed tags: " + str(sroutelist))


def maas_exact_tags(session, current_tags, module_tags, module, res):
    """
    Given a list of tags, remove and add/update as needed
    to make reality match the list
    """
    wanted = []
    wanted_delete = []
    wanted_add_update = []

    module_tags_dict = {k["destination"]: k for k in module_tags}

    wanted = module_tags_dict.keys()

    for sroute in current_tags:
        dest = sroute["destination"]
        if (dest["name"] not in wanted) and (dest["cidr"] not in wanted):
            wanted_delete.append(sroute)
        else:
            wanted_add_update.append(sroute)

    for sroute in module_tags:
        if (
            matching_route := lookup_static_route(
                sroute["destination"], current_tags, module
            )
        ) is None:
            wanted_add_update.append(sroute)

    if wanted_delete:
        maas_delete_tags(session, current_tags, wanted_delete, module, res)

    if wanted_add_update:
        maas_add_tags(session, current_tags, wanted_add_update, module, res)


def run_module():
    module_args = dict(
        tags=dict(type="list", required=True),
        password=dict(type="str", required=True, no_log=True),
        username=dict(type="str", required=True),
        site=dict(type="str", required=True),
        state=dict(type="str", required=False, default="present"),
    )

    result = dict(changed=False, message=[], diff={})

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib("requests"))

    if not HAS_REQUESTS_OAUTHLIB:
        module.fail_json(msg=missing_required_lib("requests_oauthlib"))

    # validate_module_parameters(module)

    response = grab_maas_apikey(module)
    api_cred = maas_api_cred(response.json())

    maas_session = OAuth1Session(
        api_cred.client_key,
        resource_owner_key=api_cred.resource_owner_key,
        resource_owner_secret=api_cred.resource_owner_secret,
        signature_method="PLAINTEXT",
    )

    # We need to key on both of these. Probably more pythonic ways
    # of doing this.

    current_tags_dict = {
        item["destination"]["name"]: item
        for item in get_maas_tags(maas_session, module)
    }

    if module.params["state"] == "present":
        maas_add_tags(
            maas_session,
            current_tags_dict,
            module.params["tags"],
            module,
            result,
        )

    elif module.params["state"] == "absent":
        maas_delete_tags(
            maas_session,
            current_tags_dict,
            module.params["tags"],
            module,
            result,
        )

    elif module.params["state"] == "exact":
        if module.params["tags"]:
            maas_exact_tags(
                maas_session,
                current_tags_dict,
                module.params["tags"],
                module,
                result,
            )
        else:
            maas_delete_all_tags(
                maas_session,
                current_tags_dict,
                module,
                result,
            )

    module.exit_json(**result)


def validate_module_parameters(module):
    """
    Perform simple validations on module parameters
    """
    tags = module.params["tags"]


def main():
    run_module()


if __name__ == "__main__":
    main()
