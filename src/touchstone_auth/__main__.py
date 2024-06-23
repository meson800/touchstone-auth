from touchstone_auth import TouchstoneSession, UsernamePassAuth, TwofactorType
from bs4 import BeautifulSoup  # type: ignore
import json
from argparse import ArgumentParser

parser = ArgumentParser(prog='touchstone-auth-debugger')
parser.add_argument('--url', default='https://atlas.mit.edu', required=False)
parser.add_argument('--credentials', default='credentials.json', required=False)

if __name__ == '__main__':
    # For debugging
    args = parser.parse_args()
    print("Debugging session")

    with open(args.credentials, encoding='utf-8') as configfile:
        config = json.load(configfile)

    with TouchstoneSession(args.url,
            # Username/pass auth
            auth_type=UsernamePassAuth(config['username'], config['password']), cookiejar_filename='cookiejar.pickle',
            twofactor_type=TwofactorType.DUO_PUSH,
            verbose=True) as s:
        r = s.get(args.url)
        parsed_html = BeautifulSoup(r.text, features='html.parser')
        print(f"Title: {parsed_html.find('title').string}")
