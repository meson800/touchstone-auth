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
from touchstone_auth import TouchstoneSession

with open('credentials.json') as cred_file:
    credentials = json.load(cred_file)

with TouchstoneSession(
    base_url='https://atlas.mit.edu',
    pkcs12_filename=credentials['certfile'],
    pkcs12_pass=credentials['password'],
    cookiejar_filename='cookies.pickle') as s:

    response = s.get('https://atlas.mit.edu/atlas/Main.action')
```

When you call this the first time, your Python script will hang on the 2FA step until
the Duo push is accepted. Subsequent requests should not block until the 30-day
"remember me" period is exceeded.

If this blocking behavior is undesired, you can set the argument `should_block=False`
in the `TouchstoneSession` constructor. If a blocking 2FA push is required, the error
`WouldBlockError` will instead be raised.

Finally, there is a `verbose` argument; setting `verbose=True` will output extra
information about how processing is proceeding.

## Complete Examples

### Get your latest paystub from ADP:
```
import json
from touchstone_auth import TouchstoneSession

with open('credentials.json') as cred_file:
    credentials = json.load(cred_file)

with TouchstoneSession(
    base_url='https://myadp.mit.edu',
    pkcs12_filename=credentials['certfile'],
    pkcs12_pass=credentials['password'],
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

## License
This is licensed by the MIT license. Use freely!