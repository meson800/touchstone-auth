from touchstone_auth import TouchstoneSession, UsernamePassAuth, TwofactorType
from bs4 import BeautifulSoup  # type: ignore
import json

if __name__ == '__main__':
    # For debugging
    print("Debugging session")

    with open('credentials.json', encoding='utf-8') as configfile:
        config = json.load(configfile)

    with TouchstoneSession('https://atlas.mit.edu',
            # Username/pass auth
            auth_type=UsernamePassAuth(config['username'], config['password']), cookiejar_filename='cookiejar.pickle',
            # Certificate auth
            #auth_type=CertificateAuth(config['certfile'], config['password']), cookiejar_filename='cookiejar.pickle',
            # Byte-loaded certificate auth
            #auth_type=CertificateAuth(open(config['certfile'], 'rb').read(), config['password']), cookiejar_filename='cookiejar.pickle',
            # Deprecated certificate auth
            #config['certfile'], config['password'], cookiejar_filename='cookiejar.pickle',
            twofactor_type=TwofactorType.DUO_PUSH,
            verbose=True) as s:
        r = s.get('https://atlas.mit.edu')
        parsed_html = BeautifulSoup(r.text, features='html.parser')
        print(parsed_html.find('title').string)
