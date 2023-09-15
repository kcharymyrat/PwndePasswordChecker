import requests
import hashlib
import argparse
import sys


def get_sha1_in_upper(password):
    sha1 = hashlib.sha1()
    sha1.update(password.encode())
    return sha1.hexdigest().upper()


def pwned_api_check(password):
    """Check if a password has been pwned."""
    sha1_password = get_sha1_in_upper(password)
    response = requests.get(f'https://api.pwnedpasswords.com/range/{sha1_password[:5]}')
    return get_breaches_count(response, sha1_password[5:]), sha1_password


def get_breaches_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def main(show_hash):
    while True:
        password = input('Enter your password (or "exit" to quit): ')
        if password.lower() == 'exit':
            print("Goodbye!")
            sys.exit(0)
        count, sha1password = pwned_api_check(password)
        if show_hash:
            print(f'Full hashed password: {sha1password}')
        if count:
            print(f'Your password has been pwned! It appears {count} times in data breaches.')
        else:
            print('Your password has not been pwned. Good job!')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check if a password has been pwned.')
    parser.add_argument('--show-hash', action='store_true', help='Show the full hashed password in the output')
    args = parser.parse_args()
    main(args.show_hash)
