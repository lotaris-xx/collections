#!/usr/bin/python

from __future__ import absolute_import, division, print_function
from ansible.module_utils.basic import missing_required_lib

from yaml import safe_dump
from ipaddress import ip_address, ip_network

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

STATIC_ROUTE_SUPPORTED_KEYS = ["source", "destination", "gateway_ip", "metric", "id"]
STATIC_ROUTE_MODIFY_KEYS = ["source", "gateway_ip", "metric"]

__metaclass__ = type

DOCUMENTATION = r"""
---
module: maas_static_routes

short_description: Configure MAAS static_routes

version_added: "1.0.0"

description: Configure MAAS static_routes

options:
    password:
        description: Password for username used to get API token. Mutually excludive with O(token).
        required: true
        type: str
    site:
        description: URL of the MAAS site (generally ending in /MAAS)
        required: true
        type: str
    state:
        description:
          - if V(absent) then the static_route(s) will be removed if currently present.
          - if V(present) then the static_route(s) will be created/updated.
          - if V(exact) then the resulting static_route list will match what is passed in.
        required: false
        type: str
        default: present
        choices: [ absent, present, exact ]
    username:
        description: Username to get API token. Mutually exclusive with O(token).
        required: true
        type: str
    static_routes:
        description: A list containing static_route specifier dictionaries
        required: true
        type: list
        suboptions:
          source:
              description: The CIDR of source network
              required: true
              type: str
          destination:
              description: The CIDR of the dest network
              required: true
              type: str
          gateway_ip:
              description: The gateway IP address
              required: true
              type: str
          metric:
              description: The weight of the route
              required: false
              type: int
    token:
        description: API Token, a string in 3 parts separated by ':'. Mutually exclusive with O(username)/O(password).
        required: true
        type: string

notes:
   - The puppet code this is based on keys off the destination (assuming each destination
     is listed once) so this code does the same.

requirements:
   - requests
   - requests-oauthlib

author:
    - Allen Smith (@asmith-tmo)
"""

EXAMPLES = r"""
# Add/Remove as needed to exactly match given list
-  maas_static_routes:
     username: user
     password: password
     state: exact
     static_routes:
       - source: 10.23.1.0/24
         destination: 1.2.0.0/16
         gateway_ip: 10.23.1.1
       - source: 10.23.1.0/24
         destination: 192.168.66.0/24
         gateway_ip: 10.23.1.1
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


def static_route_needs_updating(current, wanted, module):
    """
    Compare two static_route definitions and see if there are differences
    in the fields we allow to be changed
    """

    ret = False
    current_filtered = {
        k: v for k, v in current.items() if k in STATIC_ROUTE_MODIFY_KEYS
    }
    wanted_filtered = {k: v for k, v in wanted.items() if k in STATIC_ROUTE_MODIFY_KEYS}

    # We need to compare manually as source may match name or cidr attributes
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


def get_maas_static_routes(session, module):
    """
    Grab the current list of static_routes
    """
    try:
        filtered_static_routes = []
        current_static_routes = session.get(
            f"{module.params['site']}/api/2.0/static-routes/"
        )
        current_static_routes.raise_for_status()

        # filter the list down to keys we support
        for static_route in current_static_routes.json():
            filtered_static_routes.append(
                {
                    k: v
                    for k, v in static_route.items()
                    if k in STATIC_ROUTE_SUPPORTED_KEYS
                }
            )
        return filtered_static_routes
    except exceptions.RequestException as e:
        module.fail_json(
            msg="Failed to get current static_route list: {}".format(str(e))
        )


def lookup_static_route(lookup, current_sroutes, module):
    """
    Given a lookup return a static route if the lookup
    matches either the name or cidr property of a current route
    """
    ret = None

    for item in current_sroutes.keys():
        if lookup["destination"] in [
            current_sroutes[item]["destination"]["name"],
            current_sroutes[item]["destination"]["cidr"],
        ]:
            ret = current_sroutes[item]

    return ret


def maas_add_static_routes(
    session, current_static_routes, wanted_static_routes, module, res
):
    """
    Given a list of static_routes to add, we add those that don't exist
    If they exist, we check if something has changed and if it
    is a parameter that we can update, we call a function to do
    that.
    """
    sroutelist_added = []
    sroutelist_updated = []

    for static_route in wanted_static_routes:
        if "metric" not in static_route.keys():
            static_route["metric"] = 0

        if (
            matching_route := lookup_static_route(
                static_route, current_static_routes, module
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
                        msg=f"static_route Add Failed: {format(str(e))} with {r.text} and {format(static_route)}"
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

    new_static_routes_dict = {
        item["destination"]["name"]: item
        for item in get_maas_static_routes(session, module)
    }

    res["diff"] = dict(
        before=safe_dump(current_static_routes),
        after=safe_dump(new_static_routes_dict),
    )

    if sroutelist_added:
        res["message"].append("Added static_routes: " + str(sroutelist_added))

    if sroutelist_updated:
        res["message"].append("Updated static_routes: " + str(sroutelist_updated))


def maas_delete_all_static_routes(session, current_static_routes, module, res):
    """
    Delete all static routes
    """
    sroutelist = []

    for item in current_static_routes:
        sroute = current_static_routes[item]
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
                    msg=f"static_route Remove Failed: {format(str(e))} with {format(current_static_routes)}"
                )

            new_static_routes_dict = {
                item["destination"]["name"]: item
                for item in get_maas_static_routes(session, module)
            }

            res["diff"] = dict(
                before=safe_dump(current_static_routes),
                after=safe_dump(new_static_routes_dict),
            )

    if sroutelist:
        res["message"].append("Removed static_routes: " + str(sroutelist))


def maas_delete_static_routes(
    session, current_static_routes, module_static_routes, module, res
):
    """
    Given a list of static_routes to remove, we delete those that exist"
    """
    sroutelist = []

    for sroute in module_static_routes:
        if (
            matching_route := lookup_static_route(sroute, current_static_routes, module)
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
                        msg=f"static_route Remove Failed: {format(str(e))} with {format(current_static_routes)}"
                    )

                new_static_routes_dict = {
                    item["destination"]["name"]: item
                    for item in get_maas_static_routes(session, module)
                }

                res["diff"] = dict(
                    before=safe_dump(current_static_routes),
                    after=safe_dump(new_static_routes_dict),
                )

    if sroutelist:
        res["message"].append("Removed static_routes: " + str(sroutelist))


def maas_exact_static_routes(
    session, current_static_routes, wanted_static_routes, module, res
):
    """
    Given a list of static_routes, remove and add/update as needed
    to make reality match the list
    """
    dest = {}
    wanted = []
    wanted_delete = []
    wanted_add_update = []

    module_static_routes_dict = {k["destination"]: k for k in wanted_static_routes}

    wanted = module_static_routes_dict.keys()

    for sroute in current_static_routes.keys():
        dest = current_static_routes[sroute]["destination"]
        if (dest["name"] not in wanted) and (dest["cidr"] not in wanted):
            wanted_delete.append(sroute)
        else:
            selector = dest["name"] if dest["name"] in wanted else dest["cidr"]
            wanted_add_update.append(module_static_routes_dict[selector])

    for sroute in wanted_static_routes:
        if (lookup_static_route(sroute, current_static_routes, module)) is None:
            wanted_add_update.append(sroute)

    if wanted_delete:
        maas_delete_static_routes(
            session, current_static_routes, wanted_delete, module, res
        )

    if wanted_add_update:
        maas_add_static_routes(
            session, current_static_routes, wanted_add_update, module, res
        )


def run_module():
    module_args = dict(
        static_routes=dict(type="list", elements="dict", required=True),
        password=dict(type="str", no_log=True),
        username=dict(type="str"),
        site=dict(type="str", required=True),
        state=dict(type="str", required=False, default="present"),
        token=dict(type="str", no_log=True),
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

    validate_module_parameters(module)

    response = grab_maas_apikey(module)
    api_cred = maas_api_cred(response.json())

    maas_session = OAuth1Session(
        api_cred.client_key,
        resource_owner_key=api_cred.resource_owner_key,
        resource_owner_secret=api_cred.resource_owner_secret,
        signature_method="PLAINTEXT",
    )

    current_static_routes_dict = {
        item["destination"]["name"]: item
        for item in get_maas_static_routes(maas_session, module)
    }

    if module.params["state"] == "present":
        maas_add_static_routes(
            maas_session,
            current_static_routes_dict,
            module.params["static_routes"],
            module,
            result,
        )

    elif module.params["state"] == "absent":
        maas_delete_static_routes(
            maas_session,
            current_static_routes_dict,
            module.params["static_routes"],
            module,
            result,
        )

    elif module.params["state"] == "exact":
        if module.params["static_routes"]:
            maas_exact_static_routes(
                maas_session,
                current_static_routes_dict,
                module.params["static_routes"],
                module,
                result,
            )
        else:
            maas_delete_all_static_routes(
                maas_session,
                current_static_routes_dict,
                module,
                result,
            )

    module.exit_json(**result)


def validate_module_parameters(module):
    """
    Perform simple validations on module parameters
    """
    static_routes = module.params["static_routes"]

    # Ensure we have all keys that we support modifying so that
    # We can easily compare and detect needed changes

    for sroute in static_routes:
        if "metric" not in sroute.keys():
            sroute["metric"] = 1

        # Validate IP related info

        try:
            if "source" in sroute.keys():
                source_network = ip_network(sroute["source"])

        except ValueError as e:
            module.fail_json(msg="Source network is invalid: {}".format(str(e)))

        try:
            ip_network(sroute["destination"])

        except ValueError as e:
            module.fail_json(msg="Destination network is invalid: {}".format(str(e)))

        try:
            if "gateway_ip" in sroute.keys():
                gateway_ip = ip_address(sroute["gateway_ip"])

                if gateway_ip not in source_network:
                    module.fail_json(
                        msg=f"The gateway IP {gateway_ip} is not in the source {source_network}"
                    )

        except ValueError as e:
            module.fail_json(msg="Gateway IP address is invalid: {}".format(str(e)))


def main():
    run_module()


if __name__ == "__main__":
    main()
