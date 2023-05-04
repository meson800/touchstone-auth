"""
Implements a helper class that is responsible for logging into a
Touchstone-protected MIT SSO site. This enables programatic access
to Touchstone services by a user. No authentication flow is blocked
or bypassed; this simply allows programmatic access to Duo 2FA
and Touchstone auth outside of a web browser.
"""
from dataclasses import dataclass
import enum
import functools
import json
import pathlib
import pickle
import re
from typing import Optional, Union
import warnings
try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal


from bs4 import BeautifulSoup  # type: ignore
import requests
import requests.utils
from requests_pkcs12 import Pkcs12Adapter  # type: ignore
from requests_kerberos import HTTPKerberosAuth  # type: ignore

class TouchstoneError(RuntimeError):
    """Represents all returnable Touchstone Errors"""

class WouldBlockError(TouchstoneError):
    """Called when a 2FA blocking push is required in non-blocking mode"""

class TwofactorType(enum.Enum):
    DUO_PUSH = enum.auto()
    PHONE_CALL = enum.auto()

@dataclass
class CertificateAuth:
    """
    Use a password-protected certificate for initial authentication.
    
    The passed certificate file can either be a bytes object (for the actual cert)
    or a string/path to a certificate file.
    """
    pkcs12_cert: Union[str,pathlib.Path,bytes]
    pkcs12_pass: str

@dataclass
class UsernamePassAuth:
    """
    Use a username and password for initial authentication.

    Do not hard code credentials in your script!
    """
    username: str
    password: str

@dataclass
class KerberosAuth:
    """
    Use Kerberos tickets for initial authentication.
    """

def deprecate_nonurl_args(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if len(args) > 2:
            warnings.warn(
                'Passing arguments except for the base URL by position will be removed! Pass by keyword instead.',
                DeprecationWarning
            )
        return f(*args, **kwargs)
    return wrapper

class TouchstoneSession:
    """
    This is a wrapper context manager class for requests.Session.
    In addition to tracking cookies across requests, a TouchstoneSession
    saves/loads the cookiejar to a file so that it is persistant across runs.
 
    In addition, this session properly logs in using Touchstone and Duo if needed.
    """
    @deprecate_nonurl_args
    def __init__(self,
        base_url:str,
        pkcs12_filename:Optional[Union[str,pathlib.Path]]=None,
        pkcs12_pass:Optional[str]=None,
        cookiejar_filename:Union[str,pathlib.Path]='cookiejar.pickle',
        should_block:bool=True,
        twofactor_type:TwofactorType=TwofactorType.DUO_PUSH,
        verbose:bool=False,
        *,
        auth_type:Optional[Union[CertificateAuth,UsernamePassAuth,KerberosAuth]]=None,
        autosave_cookies:bool=True) -> None:
        """
        Creates a new Touchstone session.

        Arguments
        ---------
        base_url: a URL specifying the MIT SSO service to login to.
        pkcs12_filename: (Deprecated) A location of a password-protected client certificate (.p12)
        pkcs12_pass: (Deprecated)The password to the client certificate. Don't hard code this!
        cookiejar_filename: The location to persist cookies at.
        should_block: If False, if a Duo 2FA push is required, we instead raise a
            WouldBlockError. Does not error if cookies are recent enough to avoid 2FA.
        twofactor_type: The desired second factor to use for Duo authentication.
            Only Duo Push (TwofactorType.DUO_PUSH) and phone call (TwofactorType.PHONE_CALL)
            are currently supported.
        verbose: If True, extra information during log-in is printed to stdout
        auth_type: Determines the type of authentication to use. Pass an enum type.
        autosave_cookies: If cookies should be automatically re-saved back to the same cookiejar file
            when the session is closed.
        """

        self._session: requests.Session = requests.Session()
        self._base_url = base_url
        if auth_type is not None:
            # Check for invalid behavior
            if pkcs12_filename is not None or pkcs12_pass is not None:
                raise ValueError("Cannot pass both auth_type and the deprecated pkcs12_filename/pass at the same time!")
            if type(auth_type) not in [CertificateAuth,UsernamePassAuth,KerberosAuth]:
                raise TypeError("Invalid authentication type. Expecting a CertificateAuth, UsernamePassAuth, or KerberosAuth.")
            self._auth = auth_type
        else:
            self._auth = CertificateAuth(pkcs12_filename, pkcs12_pass)
        self._cookiejar_filename = cookiejar_filename
        self._blocking = should_block
        self._twofactor_type = twofactor_type
        self._verbose = verbose
        self._session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/112.0'
        })
        self._autosave_cookies = autosave_cookies

        # Load cookiejar from path (if it exists)
        try:
            with open(cookiejar_filename, 'rb') as cookies:
                self._session.cookies.update(pickle.load(cookies))
        except FileNotFoundError:
            pass
        
        # Attempt to get the base URL
        initial_response = self._session.get(self._base_url)
        # Check to see the final URL to see if we have to do something
        if not initial_response.url.startswith(r'https://idp.mit.edu/idp'):
            # Attempt loading a bearer token
            self.load_bearer_token(initial_response)
            self.vlog('Logged in successfully to {} without redirecting through Touchstone'.format(
                base_url))
            return

        if initial_response.request.url is None:
            raise ValueError("initial_response.request.url is None")
        req_url: str = initial_response.request.url

        # Check which IDP page we got redirected to
        match = re.match(
            r'https:\/\/idp\.mit\.edu\/idp\/Authn\/MIT\?conversation=(.*)',
            initial_response.request.url)
        if match is None:
            # Check if we need to do the SSO login now
            if (initial_response.url.startswith(r'https://idp.mit.edu/idp/profile/SAML2/Redirect/SSO') or
                initial_response.url.startswith(r'https://idp.mit.edu/idp/profile/SAML2/Unsolicited/SSO')):
                self.vlog('Touchstone cookies still up to date; performing SSO redirect.')
                self.perform_sso(initial_response)
            else:
                self.vlog('We are not in the Touchstone auth or SSO flow! Terminal URL: {}'.format(
                    initial_response.url))
                raise TouchstoneError('Invalid Touchstone state detected (not in Touchstone auth or SSO flow)')
        else:
            self.vlog('Performing certificate/Duo login...')
            touchstone_response = self.perform_touchstone(match.group(1))
            self.vlog('Performing SSO login post-Duo')
            self.perform_sso(touchstone_response)

    def load_bearer_token(self, response: requests.Response) -> None:
        """
        Attempts to load a Bearer token from the final successful redirect.
        """
        match = re.search(r".*access_token=([^&]*)&id_token=[^&]*(?:&state=[^&]*)?&token_type=Bearer", response.url)
        if match is not None:
            self._session.headers.update({'authorization': 'Bearer {}'.format(match.group(1))})
            self.vlog('Bearer token loaded!')

    def perform_touchstone(self, conversation):
        """
        Performs Touchstone and Duo login procedures (handling redirects to/from Duo)

        Arguments
        ---------
        conversation: A string specifying the Touchstone conversation type.
        """
        auth_kwargs = {}
        if type(self._auth) == CertificateAuth:
            if type(self._auth.pkcs12_cert) == bytes:
                self._session.mount('https://idp.mit.edu', Pkcs12Adapter(
                    pkcs12_data=self._auth.pkcs12_cert,
                    pkcs12_password=self._auth.pkcs12_pass))
            else:
                self._session.mount('https://idp.mit.edu', Pkcs12Adapter(
                    pkcs12_filename=self._auth.pkcs12_cert,
                    pkcs12_password=self._auth.pkcs12_pass))
            r = self._session.get('https://idp.mit.edu:446/idp/Authn/Certificate',params={
                'login_certificate': 'Use Certificate - Go',
                'conversation': conversation
            })
        elif type(self._auth) == UsernamePassAuth:
            r = self._session.post('https://idp.mit.edu:446/idp/Authn/UsernamePassword',params={
                'j_username': self._auth.username,
                'j_password': self._auth.password,
                'Submit': 'Login',
                'conversation': conversation
            })
        elif type(self._auth) == KerberosAuth:
            auth_kwargs['auth'] = HTTPKerberosAuth()
            r = self._session.get('https://idp.mit.edu:446/idp/Authn/Kerberos',params={
                'login_kerberos': 'Use existing tickets - Go',
                'conversation': conversation
            }, **auth_kwargs)
        else:
            raise TypeError("Incorrect auth type passed!")

        duo_html = BeautifulSoup(r.text, features='html.parser')
        duo_container = duo_html.find(id='duo_container')
        if duo_container is None:
            raise TouchstoneError("Initial authentication with {} failed".format(type(self._auth).__name__))
        duo_script = duo_container.findChildren('script')[1].string

        # Get parent URL
        parent_url =  r.url

        # Clean up json string before decoding
        duo_connect_string = re.search(
            r'Duo.init\(({[\S\s]*})\);',
            duo_script).group(1).replace("'",'"')
        duo_json = json.loads(duo_connect_string)
        duo_tx, duo_app = duo_json['sig_request'].split(':')

        self.vlog('Decoded Touchstone Duo redirect request')

        # POST to Duo, which will 302 redirect, giving us the prompt SID
        duo_connect_params = {
            'tx': duo_tx,
            'parent': parent_url,
            'v': '2.6'
        }

        duo_prompt_data = {
                    # Why do we have to provide tx and parent both in params and data? No idea...
                    'tx': duo_connect_params['tx'],
                    'parent': duo_connect_params['parent'],
                    'java_version': '',
                    'flash_version': '',
                    'screen_resolution_width': '2560',
                    'screen_resolution_height': '1440',
                    'color_depth': '32',
                    'ch_ua_error': '',
                    'client_hints': '',
                    'is_cef_browser': 'false',
                    'is_ipad_os': 'false',
                    'is_ie_compatibility_mode': '',
                    'is_user_verifying_platform_authenticator_available': 'false',
                    'user_verifying_platform_authenticator_available_error': '',
                    'acting_ie_version': '',
                    'react_support': 'true',
                    'react_support_error_message': ''
        }
        # Get the URL first to set the xsrf cookie
        _xsrf_get = self._session.get(f"https://{duo_json['host']}/frame/web/v1/auth",
                params=duo_connect_params
        )
        # Post to get the redirect
        auth_request = self._session.post(f"https://{duo_json['host']}/frame/web/v1/auth",
                params=duo_connect_params,
                data=duo_prompt_data
        )
        if len(auth_request.history) > 0:
            # A redirect happened, do the full auth flow if we have time to block
            if not self._blocking:
                raise WouldBlockError('Second factor auth required, but blocking is not allowed')
            self.vlog('Second factor auth required: requested Duo auth page')

            prompt_url = auth_request.request.url
            prompt_sid = re.match(r".*\/frame\/prompt\?sid=(.*)", prompt_url).group(1)
            extra_prompt_headers = {
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Referer': prompt_url,
                'X-Requested-With': 'XMLHttpRequest',
                'Origin': f"https://{duo_json['host']}"
            }

            # POST to send the push
            factor = {
                TwofactorType.DUO_PUSH: 'Duo+Push',
                TwofactorType.PHONE_CALL: 'Phone+Call'
            }[self._twofactor_type]
            r = self._session.post(f"https://{duo_json['host']}/frame/prompt",
                    # Push data through as raw bytes; this is the correct URL encoding
                    # (don't let requests mess with it by sending as a dict)
                    data=bytes(
                        f"sid={prompt_sid}&device=phone1&factor={factor}&cookies_allowed=true&dampen_choice=true&out_of_date=&days_out_of_date=&days_to_block=None",
                        'utf-8'),
                    headers=extra_prompt_headers)

            self.vlog(f'Requested second factor authentication ({factor})')

            prompt_response = json.loads(r.text)
            if prompt_response['stat'] != 'OK':
                raise TouchstoneError("Unable to send two-factor request")

            # Do a first request (this returns the info 'Pushed a login request to your device')
            r = self._session.post(f"https://{duo_json['host']}/frame/status",
                data=bytes(f"sid={prompt_sid}&txid={prompt_response['response']['txid']}", 'utf-8'),
                headers=extra_prompt_headers)
            expected_return_status = {
                TwofactorType.DUO_PUSH: 'pushed',
                TwofactorType.PHONE_CALL: 'calling'
            }[self._twofactor_type]
            if json.loads(r.text)['response']['status_code'] != expected_return_status:
                raise TouchstoneError(f"Second-factor auth (self._twofactor_type) failed")


            # Block until the user does something with the request
            if self._twofactor_type == TwofactorType.DUO_PUSH:
                self.vlog('Successfully pushed Duo push request. Blocking until response...')
                r = self._session.post(f"https://{duo_json['host']}/frame/status",
                    data=bytes(f"sid={prompt_sid}&txid={prompt_response['response']['txid']}", 'utf-8'),
                    headers=extra_prompt_headers)
                post_prompt_response = json.loads(r.text)
                self.vlog(post_prompt_response)
                if post_prompt_response['stat'] != 'OK':
                    raise TouchstoneError("User declined prompt or prompt timed out")

                self.vlog('Second factor auth successful!')
            elif self._twofactor_type == TwofactorType.PHONE_CALL:
                self.vlog('Successfully pushed phone call request...')
                r = self._session.post(f"https://{duo_json['host']}/frame/status",
                    data=bytes(f"sid={prompt_sid}&txid={prompt_response['response']['txid']}", 'utf-8'),
                    headers=extra_prompt_headers)
                post_request_response = json.loads(r.text)
                if (post_request_response['stat'] != 'OK' or 
                    post_request_response['response']['status_code'] != 'calling'):
                    raise TouchstoneError("Unable to call registered phone number.")
                self.vlog(post_request_response['response']['status'])
                # After the dialing response, we expect the answered response.
                r = self._session.post(f"https://{duo_json['host']}/frame/status",
                    data=bytes(f"sid={prompt_sid}&txid={prompt_response['response']['txid']}", 'utf-8'),
                    headers=extra_prompt_headers)
                post_request_response = json.loads(r.text)
                if (post_request_response['stat'] != 'OK' or 
                    post_request_response['response']['status_code'] != 'answered'):
                    raise TouchstoneError("Twofactor call declined.")
                self.vlog("Two-factor call answered. Waiting for user input...")
                # Check for successful response
                r = self._session.post(f"https://{duo_json['host']}/frame/status",
                    data=bytes(f"sid={prompt_sid}&txid={prompt_response['response']['txid']}", 'utf-8'),
                    headers=extra_prompt_headers)
                post_prompt_response = json.loads(r.text)
                if (post_prompt_response['stat'] != 'OK' or 
                    post_prompt_response['response']['status_code'] != 'allow'):
                    raise TouchstoneError("Two-factor call failed.")
                self.vlog('Second factor auth successful!')
            else:
                raise TouchstoneError('Unknown two-factor flow')

            # Get the AUTH token
            r = self._session.post(f"https://{duo_json['host']}{post_prompt_response['response']['result_url']}",
                data=bytes(f"sid={prompt_sid}", 'utf-8'),
                headers=extra_prompt_headers)
            auth_result = json.loads(r.text)
            if auth_result['stat'] != 'OK':
                raise TouchstoneError("Unable to get Touchstone auth token")
            duo_auth_info = auth_result['response']
        else:
            self.vlog('Duo push not required: extracting auth token')
            auth_html = BeautifulSoup(auth_request.text, features='html.parser')
            duo_auth_info = {
                'parent': auth_html.find('input', {'id': 'js_parent'})['value'],
                'cookie': auth_html.find('input', {'id': 'js_cookie'})['value']
            }


        self.vlog('Acquired Touchstone auth token')
        # Post back to the parent, returning the request back to use for SSO login
        return self._session.post(duo_auth_info['parent'],
            data={
                'sig_response': f"{duo_auth_info['cookie']}:{duo_app}"
            }, **auth_kwargs)

    def perform_sso(self, request) -> None:
        """
        Given a Request object, attempts to perform Touchstone SSO redirect by
        extracting form fields and POSTing to the right location.
        """
        touchstone_html = BeautifulSoup(request.text, features='html.parser')
        touchstone_form = touchstone_html.find('form')

        self.vlog('Posting SSO redirect')

        r = self._session.post(touchstone_form.attrs['action'], data={
            'RelayState': touchstone_form.find('input', {'name': 'RelayState'})['value'],
            'SAMLResponse': touchstone_form.find('input', {'name': 'SAMLResponse'})['value']
        })
        if r.url.startswith('https://idp.mit.edu'):
            raise TouchstoneError('SSO redirect unsuccessful')

        self.vlog('SSO redirect successful!')
        self.load_bearer_token(r)

    def vlog(self, string: str) -> None:
        """
        Logs a string to stdout if verbose is True
        """
        if self._verbose:
            print(string)

    def __enter__(self) -> requests.Session:
        """Returns the internal session when called as a context manager"""
        return self._session
    
    def save_cookies(self, cookiejar: Union[str,pathlib.Path]) -> None:
        """Saves session cookies into a cookiejar file, overwriting if present"""
        # Save cookiejar
        with open(cookiejar, 'wb') as cookies:
            pickle.dump(self._session.cookies, cookies)


    def close(self) -> None:
        """Closes the session while saving the session cookies."""
        # Save cookies if we are autosaving...
        if self._autosave_cookies:
            self.save_cookies(self._cookiejar_filename)
        # and close the internal session
        self._session.close()

    def __exit__(self, ex_type, value, traceback) -> Literal[False]:
        self.close()
        return False

# For debugging
if __name__ == '__main__':
    with open('credentials.json', encoding='utf-8') as configfile:
        config = json.load(configfile)

    with TouchstoneSession('https://atlas.mit.edu',
            # Username/pass auth
            #auth_type=UsernamePassAuth(config['username'], config['password']), cookiejar_filename='cookiejar.pickle',
            # Certificate auth
            #auth_type=CertificateAuth(config['certfile'], config['password']), cookiejar_filename='cookiejar.pickle',
            # Byte-loaded certificate auth
            auth_type=CertificateAuth(open(config['certfile'], 'rb').read(), config['password']), cookiejar_filename='cookiejar.pickle',
            # Deprecated certificate auth
            #config['certfile'], config['password'], cookiejar_filename='cookiejar.pickle',
            twofactor_type=TwofactorType.DUO_PUSH,
            verbose=True) as s:
        s.get('https://atlas.mit.edu')
