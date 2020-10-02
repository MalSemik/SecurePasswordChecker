import requests
import hashlib
import PySimpleGUI as sg


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for hash, count in hashes:
        if hash == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_5_char, rest_of_hash = sha1password[:5], sha1password[5:]
    response = request_api_data(first_5_char)
    leaks_count = get_password_leaks_count(response, rest_of_hash)
    return leaks_count


password = sg.popup_get_text('Password', password_char='*')
leaks_count = pwned_api_check(password)
if leaks_count == 0:
    sg.popup("This password never leaked, you're good to go!")
else:
    sg.popup(f'This password leaked {leaks_count} times.')