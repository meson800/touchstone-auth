from dataclasses import dataclass
from typing import Any, Dict
import re

import touchstone_auth.sso

@dataclass
class Remediation:
    name: str
    url: str
    http_method: str
    data: Dict[str,Any]

BLACKLISTED_REMEDIATIONS = ['unlock-account']

def select_remediation(remediations, available_data) -> Remediation:
    """
    Given an Okta set of remediations and our available data,
    returns a dataclass representing which remediation to take
    """
    for remediation_option in remediations:
        if remediation_option['name'] in BLACKLISTED_REMEDIATIONS:
            continue
        name = remediation_option['name']
        url = remediation_option['href']
        method = remediation_option['method']

        # Check if we have all of the entries
        remediation_data: Dict[str,Any] = {}
        complete = True
        if 'value' in remediation_option:
            for value in remediation_option['value']:
                if 'value' in value:
                    remediation_data[value['name']] = value['value']
                else:
                    if value['name'] not in available_data:
                        complete = False
                        break
                    remediation_data[value['name']] = available_data[value['name']]
            if not complete:
                continue
        # At this point, we have a complete remediation!
        return Remediation(name=name, url=url, http_method=method, data=remediation_data)
    raise touchstone_auth.sso.TouchstoneError("Unable to locate a Okta remediation!")


def extract_state_token(request_text):
    """
    Extracts the stateToken from within the oktaState object.
    
    Raises TouchstoneErrors if unable to do so.
    
    Arguments
    ---------
    request_text: the text of the Okta response to parse.
    """
    match = re.search(r"oktaData = (?P<oktaData>{.*};)", request_text)
    if match is None:
        raise touchstone_auth.sso.TouchstoneError("Okta: Unable to extract Okta data from the Touchstone proxy page")
    # The resulting thing is not...quite JSON. Just use regexes to extract. There are embedded
    # Javascript functions and other things that break JSON parsing :( 
    unescaped = match.group(1).encode('utf-8').decode('unicode_escape')
    match = re.search(r"\"idpDiscovery\":.*\"stateToken\":\"(?P<stateToken>[^\"]+)\"", unescaped)
    if match is None:
        raise touchstone_auth.sso.TouchstoneError("Okta: Unable to extract the Okta state token!")
    return match.group(1)