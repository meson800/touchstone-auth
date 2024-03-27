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
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0'
        })
        self._autosave_cookies = autosave_cookies

        # Load cookiejar from path (if it exists)
        try:
            with open(cookiejar_filename, 'rb') as cookies:
                jar = pickle.load(cookies)
                # USEFUL FOR DEBUGGING: this lets you remove / keep cookies in the jar
                #to_delete = []
                #for cookie in jar:
                #    if not cookie.domain.endswith('duosecurity.com'):
                #        to_delete.append(cookie.name)
                #for cookie in to_delete:
                #    del jar[cookie]
                #print(jar)
                self._session.cookies.update(jar)
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
        duo_form = duo_html.find(id='plugin_form')
        if duo_form is None:
            raise TouchstoneError("Initial authentication with {} failed".format(type(self._auth).__name__))
        
        auth_url = r.url
        url_matches = re.search(r"https:\/\/(?P<domain>[^/]+)(?P<path>[^?]+)\?sid=(?P<sid>[^&]+)\&tx=(?P<tx>.*)", auth_url)
        if url_matches is None:
            raise TouchstoneError("Can't extract sid and transaction from redirect URL")
        duo_domain = url_matches.group('domain')
        duo_path = url_matches.group('path')
        duo_sid = url_matches.group('sid')


        duo_tx_field = duo_form.find('input', {'name': 'tx'})
        duo_akey_field = duo_form.find('input', {'name': 'akey'})
        duo_xsrf_field = duo_form.find('input', {'name': '_xsrf'})
        if duo_tx_field is None or duo_akey_field is None or duo_xsrf_field is None:
            raise TouchstoneError("Unable to locate required Duo fields in first /frame/frameless/v4/auth call")
        duo_tx = duo_tx_field['value']
        duo_akey = duo_akey_field['value']
        duo_xsrf = duo_xsrf_field['value']

        self.vlog('Decoded Touchstone transaction/akey/xsrf from redirect')
        
        # Build the prompt data POST
        duo_prompt_data = {
                    # Why do we have to provide tx and parent both in params and data? No idea...
                    'tx': duo_tx,
                    'parent': 'None',
                    '_xsrf': duo_xsrf,
                    'version': 'v4',
                    'akey': duo_akey,
                    'has_session_trust_analysis_feature': 'False',
                    'session_trust_extension_id': '',
                    'java_version': '',
                    'screen_resolution_width': '1920',
                    'screen_resolution_height': '1080',
                    'color_depth': '24',
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

        # Post to Duo to load required cookies and such
        r = self._session.post(auth_url, data=duo_prompt_data)
        # First one should be healthcheck
        if '/frame/v4/preauth/healthcheck' not in r.url:
            raise TouchstoneError("Didn't reach the Duo healthcheck endpoint!")
        # GET the data endpoint
        r = self._session.get(f'https://{duo_domain}/frame/v4/preauth/healthcheck/data?sid={duo_sid}')
        # and GET the return endpoint
        r = self._session.get(f'https://{duo_domain}/frame/v4/return?sid={duo_sid}')

        # Post again
        r = self._session.post(auth_url, data=duo_prompt_data)

        if r.url.startswith('https://idp.mit.edu/idp/profile/SAML2/Redirect/SSO'):
            # We're done!
            self.vlog('Duo not required: Duo cookie cached. Returning to Touchstone')
            return r

        if '/frame/v4/auth/prompt' not in r.url:
            raise TouchstoneError("Didn't reach the prompt Duo endpoint!")
        
        xsrf_search = re.search(r'\"xsrf_token\": \"([^\"]+)\"', r.text)
        if xsrf_search is None:
            raise TouchstoneError("Unable to extract XSRF token from prompt GET")
        xsrf = xsrf_search.group(1)

        if not self._blocking:
            raise WouldBlockError('Second factor auth required, but blocking is not allowed')
        self.vlog('Second factor auth required: requested Duo auth page')

        extra_prompt_headers = {
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Referer': f"https://{duo_domain}/frame/v4/auth/prompt?sid={duo_sid}",
            'X-Requested-With': 'XMLHttpRequest',
            'X-Xsrftoken': xsrf,
            'Origin': f"https://{duo_domain}"
        }

        # Get the device ID
        r = self._session.get(f"https://{duo_domain}/frame/v4/auth/prompt/data",
                # Push data through as raw bytes; this is the correct URL encoding
                # (don't let requests mess with it by sending as a dict)
                params=bytes(
                    'post_auth_action=OIDC_EXIT&browser_features={"touch_supported"%3Afalse%2C"platform_authenticator_status"%3A"unavailable"%2C"webauthn_supported"%3Atrue}&sid=' + duo_sid,
                    'utf-8'),
                headers=extra_prompt_headers
        )
        prompt_data = json.loads(r.text)
        if prompt_data['stat'] != 'OK':
            raise TouchstoneError("Unable to fetch Duo prompt data")
        device_id = prompt_data['response']['phones'][0]['key']

        # POST to send the push
        factor = {
            TwofactorType.DUO_PUSH: 'Duo+Push',
            TwofactorType.PHONE_CALL: 'Phone+Call'
        }[self._twofactor_type]
        r = self._session.post(f"https://{duo_domain}/frame/v4/prompt",
                # Push data through as raw bytes; this is the correct URL encoding
                # (don't let requests mess with it by sending as a dict)
                data=bytes(
                    f"device=phone1&factor={factor}&postAuthDestination=OIDC_EXIT&browser_features=%7B%22touch_supported%22%3Afalse%2C%22platform_authenticator_status%22%3A%22unavailable%22%2C%22webauthn_supported%22%3Atrue%7D&sid={duo_sid}",
                    'utf-8'),
                headers=extra_prompt_headers
        )

        self.vlog(f'Requested second factor authentication ({factor})')

        prompt_response = json.loads(r.text)
        if prompt_response['stat'] != 'OK':
            raise TouchstoneError("Unable to send two-factor request")

        # Do a first request (this returns the info 'Pushed a login request to your device')
        r = self._session.post(f"https://{duo_domain}/frame/v4/status",
            data=bytes(f"sid={duo_sid}&txid={prompt_response['response']['txid']}", 'utf-8'),
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
            r = self._session.post(f"https://{duo_domain}/frame/v4/status",
                data=bytes(f"sid={duo_sid}&txid={prompt_response['response']['txid']}", 'utf-8'),
                headers=extra_prompt_headers)
            post_prompt_response = json.loads(r.text)
            self.vlog(post_prompt_response)
            if post_prompt_response['stat'] != 'OK' or post_prompt_response['response']['status_code'] != 'allow':
                raise TouchstoneError("User declined prompt or prompt timed out")

            self.vlog('Second factor auth successful!')
        elif self._twofactor_type == TwofactorType.PHONE_CALL:
            self.vlog('Successfully pushed phone call request...')
            r = self._session.post(f"https://{duo_domain}/frame/v4/status",
                data=bytes(f"sid={duo_sid}&txid={prompt_response['response']['txid']}", 'utf-8'),
                headers=extra_prompt_headers)
            post_request_response = json.loads(r.text)
            if (post_request_response['stat'] != 'OK' or 
                post_request_response['response']['status_code'] != 'calling'):
                raise TouchstoneError("Unable to call registered phone number.")
            # After the dialing response, we expect the answered response.
            r = self._session.post(f"https://{duo_domain}/frame/v4/status",
                data=bytes(f"sid={duo_sid}&txid={prompt_response['response']['txid']}", 'utf-8'),
                headers=extra_prompt_headers)
            post_request_response = json.loads(r.text)
            if (post_request_response['stat'] != 'OK' or 
                post_request_response['response']['status_code'] != 'answered'):
                raise TouchstoneError("Twofactor call declined.")
            self.vlog("Two-factor call answered. Waiting for user input...")
            # Check for successful response
            r = self._session.post(f"https://{duo_domain}/frame/v4/status",
                data=bytes(f"sid={duo_sid}&txid={prompt_response['response']['txid']}", 'utf-8'),
                headers=extra_prompt_headers)
            post_prompt_response = json.loads(r.text)
            if (post_prompt_response['stat'] != 'OK' or 
                post_prompt_response['response']['status_code'] != 'allow'):
                raise TouchstoneError("Two-factor call failed.")
            self.vlog('Second factor auth successful!')
        else:
            raise TouchstoneError('Unknown two-factor flow')
        
        # Post to the log endpoint
        r = self._session.post(f"https://{duo_domain}/frame/prompt/v4/log_analytic",
                data={"action": "1", "page": "/frame/v4/auth/prompt", "target": "trust+browser:+yes", "browser_language": "en-US", "prompt_language": "en", "is_error": "false", "error_message": "undefined", "auth_method": factor, "auth_state": "AUTH_SUCCESS", "sid": duo_sid},
                headers=extra_prompt_headers
            )

        extra_prompt_headers = {
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Referer': f"https://{duo_domain}/frame/v4/auth/prompt?sid={duo_sid}",
            'Origin': f"https://{duo_domain}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0"
        }

        self.vlog('Duo successful! Exiting back to Touchstone')

        # Get the AUTH token
        exit_data = f"sid={duo_sid}&txid={prompt_response['response']['txid']}&factor={factor}&device_key={device_id}&_xsrf={xsrf}&dampen_choice=true"
        return self._session.post(f"https://{duo_domain}/frame/v4/oidc/exit",
            data=bytes(exit_data, 'utf-8'),
            headers=extra_prompt_headers)

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
