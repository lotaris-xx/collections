#!/usr/bin/python
try:
    from requests import post, exceptions

    HAS_REQUESTS = True
except:
    HAS_REQUESTS = False


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
