from dataclasses import dataclass
from typing import Any, Dict
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

