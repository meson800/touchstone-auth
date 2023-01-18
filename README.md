# touchstone-auth
[![PyPI-downloads](https://img.shields.io/pypi/dm/touchstone-auth)](https://pypi.org/project/touchstone-auth)
[![PyPI-version](https://img.shields.io/pypi/v/touchstone-auth)](https://pypi.org/project/touchstone-auth)
[![PyPI-license](https://img.shields.io/pypi/l/touchstone-auth)](https://pypi.org/project/touchstone-auth)
[![Supported python versions](https://img.shields.io/pypi/pyversions/touchstone-auth)](https://pypi.org/project/touchstone-auth)

## Rationale
MIT itself and MIT-adjacent organizations offer many useful web services through
a Single-Sign-On (SSO) service called Touchstone, with two-factor logins provided
by Duo. This is great, and allows easy access to many functionalities, but because
MIT does not use a commercial SSO provider (like Okta and others), there is limited
ability to access Touchstone-protected sites without a web browser.

Enter `touchstone-auth`, a Python package powered mostly by the [requests](https://docs.python-requests.org/en/master/index.html)
package! This lets user authenticate themselves programmatically. Cookies are cached,
meaning that re-authentication is only needed once cookies expire.

## Install
This package is on Pip, so you can just:
```
pip install touchstone-auth
```

Alternatively, you can get built wheels from the [Releases tab on Github](https://github.com/meson800/touchstone-auth/releases).

N.B. if installing manually, `requests_pkcs12` must be version v1.10 (`pip install` handles this automatically).

## Quickstart
The class `TouchstoneSession` is simply a `requests.Session` that performs the Touchstone
authentication flow before returning a working session to you, the authenticated user.

It is easiest to use as a context manager. Because Touchstone authentication requires a client-side certificate, remember to **not hard-code** your credentials!
The example here loads credentials from a json file called `credentials.json`:
```
{
    "certfile": "some_client_credential.p12",
    "password": "horse-battery-staple-correct"
}
```

Then, in your Python file, you can do the following:
```
import json
from touchstone_auth import TouchstoneSession, CertificateAuth

with open('credentials.json') as cred_file:
    credentials = json.load(cred_file)

with TouchstoneSession(
    base_url='https://atlas.mit.edu',
    auth_type=CertificateAuth(credentials['certfile'], credentials['password']),
    cookiejar_filename='cookies.pickle') as s:

    response = s.get('https://atlas.mit.edu/atlas/Main.action')
```

When you call this the first time, your Python script will hang on the 2FA step until
the second-factor (by default, Duo push) is accepted. Subsequent requests should not block until the 30-day
"remember me" period is exceeded.

If this blocking behavior is undesired, you can set the argument `should_block=False`
in the `TouchstoneSession` constructor. If a blocking 2FA push is required, the error
`WouldBlockError` will instead be raised.

Finally, there is a `verbose` argument; setting `verbose=True` will output extra
information about how processing is proceeding.

## Alternate authentication
You can use other authentication methods as well. 

#### Certificate as a byte array
If you have your certificate as a byte string instead of a filename, just pass the bytes as your certificate:
```
with TouchstoneSession(
    base_url='...',
    auth_type=CertificateAuth(cert_bytes, cert_password),
    cookiejar_filename='cookies.pickle') as s:
```

#### Username/password
To use your username and password (do *not* hard code your credentials in your code!), pass
a `UsernamePassAuth` instead:
```
with TouchstoneSession(
    base_url='...',
    auth_type=CertificateAuth(cert_bytes, cert_password),
    cookiejar_filename='cookies.pickle') as s:
```

#### Kerberos tickets
To authenticate using Kerberos tickets, pass `KerberosAuth()` as the `auth_type` parameter to
`TouchstoneSession`, as in:
```
with TouchstoneSession(
    base_url='...',
    auth_type=KerberosAuth(),
    cookiejar_filename='cookies.pickle') as s:
```

## Complete Examples

### Get your latest paystub from ADP:
```
import json
from touchstone_auth import TouchstoneSession, CertificateAuth

with open('credentials.json') as cred_file:
    credentials = json.load(cred_file)

with TouchstoneSession(
    base_url='https://myadp.mit.edu',
    auth_type=CertificateAuth(credentials['certfile'], credentials['password']),
    cookiejar_filename='cookies.pickle') as s:

    response = s.get('https://my.adp.com/myadp_prefix/v1_0/O/A/payStatements?adjustments=yes&numberoflastpaydates=160')
    response_json = json.loads(response.text)
    latest = response_json['payStatements'][0]
    print('Latest paystub ({}): ${} net, ${} gross'.format(
        latest['payDate'],
        latest['netPayAmount']['amountValue'],
        latest['grossPayAmount']['amountValue']))
```
which returns
`Latest paystub (2021-08-13): $XXXX.XX net, $YYYY.YY gross` when run.

### Check your Covidpass building access status:
```
import json
from touchstone_auth import TouchstoneSession, CertificateAuth

with open('credentials.json') as cred_file:
    credentials = json.load(cred_file)

with TouchstoneSession(
    base_url=r'https://atlas-auth.mit.edu/oauth2/authorize?identity_provider=Touchstone&redirect_uri=https://covidpass.mit.edu&response_type=TOKEN&client_id=2ao42ccnajj7jpqd7h059n7eoc&scope=covid19/impersonate covid19/user digital-id/search digital-id/user openid profile',
    auth_type=CertificateAuth(credentials['certfile'], credentials['password']),
    cookiejar_filename='cookies.pickle') as s:

    response = json.loads(s.get('https://api.mit.edu/pass-v1/pass/access_status').text)
    print('Current Covidpass status: {}'.format(response['status']))
```
This returns `Current Covidpass status: access_granted` if you are in fact up to date on Covidpass.

For the various "new Atlas" OAUTH2 applications, you need to find the relevant authorization URL to put as the base URL.

How did I find the proper URL for Covidpass? By looking in your browser's Developer Tools, you can locate the last GET request prior to redirect to `idp.mit.edu`, then remove the extraneous `state` parameter.

### Get the registration list for a class, using Kerberos authentication:
```
from touchstone_auth import TouchstoneSession, KerberosAuth
from bs4 import BeautifulSoup

with TouchstoneSession(base_url='https://student.mit.edu/',
                       auth_type=KerberosAuth(),
                       cookiejar_filename='cookies.pickle') as s:
    payload = {'termcode': '2023FA', 'SUBJECT01': '6.1600'}
    headers = {'Referer': 'https://student.mit.edu/cgi-bin/sfprwlst_sel.sh'}
    r = s.post('https://student.mit.edu/cgi-bin/sfprwlst.sh', data=payload, headers=headers)
    print(BeautifulSoup(r.text, 'html.parser').pre.text)
```

### Selecting two-factor method
With version 0.3.0, you can also select between phone-call and Duo Push two factor
authentication. `touchstone-auth` defaults to Duo Push if you do not select one.

To switch between the two, pass an additional `twofactor_auth` argument. For example,
to use the phone-call two factor method in the above example, additionally import
the TwofactorType enum and pass it to the session constructor:
```
import json
from touchstone_auth import TouchstoneSession, CertificateAuth, TwofactorType

with open('credentials.json') as cred_file:
    credentials = json.load(cred_file)

with TouchstoneSession(
    base_url=r'https://atlas-auth.mit.edu/oauth2/authorize?identity_provider=Touchstone&redirect_uri=https://covidpass.mit.edu&response_type=TOKEN&client_id=2ao42ccnajj7jpqd7h059n7eoc&scope=covid19/impersonate covid19/user digital-id/search digital-id/user openid profile',
    auth_type=CertificateAuth(credentials['certfile'], credentials['password']),
    cookiejar_filename='cookies.pickle',
    twofactor_type=TwofactorType.PHONE_CALL) as s:

    response = json.loads(s.get('https://api.mit.edu/pass-v1/pass/access_status').text)
    print('Current Covidpass status: {}'.format(response['status']))
```


## Developer install
If you'd like to hack locally on `touchstone-auth`, after cloning this repository:
```
$ git clone https://github.com/meson800/touchstone-auth.git
$ cd git
```
you can create a local virtual environment, and install `touchstone-auth` in "development mode"
```
$ python -m venv env
$ .\env\Scripts\activate    (on Windows)
$ source env/bin/activate   (on Mac/Linux)
$ pip install -e .
```
After this 'local install', you can use and import `touchstone-auth` freely without
having to re-install after each update.

## Changelog
See the [CHANGELOG](CHANGELOG.md) for detailed changes.
```
## [0.5.0] - 2023-01-17
### Added
- Added the ability to control cookiejar saving. Autosave can be disabled
  and the session cookies can now be saved at any time, not just on close.
```

## License
This is licensed by the MIT license. Use freely!
