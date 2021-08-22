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

Note: `requests_pkcs12` must be v1.10 in order to avoid the following error:

```
  File "/usr/local/lib/python3.9/dist-packages/requests_pkcs12.py", line 95, in __init__
    self.ssl_context = create_pyopenssl_sslcontext(pkcs12_data, pkcs12_password_bytes, ssl_protocol)
  File "/usr/local/lib/python3.9/dist-packages/requests_pkcs12.py", line 45, in create_pyopenssl_sslcontext
    ssl_context._ctx.use_certificate(cert)
  File "/usr/lib/python3/dist-packages/OpenSSL/SSL.py", line 861, in use_certificate
    raise TypeError("cert must be an X509 instance")
TypeError: cert must be an X509 instance
```

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
    cookiejar='cookies.pickle') as s:

    response = s.get('https://atlas.mit.edu/atlas/Main.action')
```

When you call this the first time, your Python script will hang on the 2FA step until
the Duo push is accepted. Subsequent requests should not block until the 30-day
"remember me" period is exceeded.

If this blocking behavior is undesired, you can set the argument `should_block=False`
in the `TouchstoneSession` constructor. If a blocking 2FA push is required, the error
`WouldBlockError` will instead be raised.

## Examples


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
