import requests
import hashlib


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}')
    return res

def get_password_leaks_conut(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for hash, count in hashes:
        print(hash, count)
def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_5_char, rest_of_hash = sha1password[:5], sha1password[5:]
    response = request_api_data(first_5_char)
    print(first_5_char, rest_of_hash)
    return get_password_leaks_conut(response, rest_of_hash)

# request_api_data('CDAFE')
pwned_api_check('123')