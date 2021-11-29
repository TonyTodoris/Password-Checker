import requests
import hashlib
import sys

def request_api_data(query_char):
	'''
	Function that requests the API Data from pwnedpasswords
	'''
	url = f"https://api.pwnedpasswords.com/range/{query_char}"
	response = requests.get(url)
	if response.status_code != 200:
		raise RuntimeError(f"Error fetching: {response.status_code}, check the API and try again")
	return response

def get_password_leaks_count(hashes, hask_to_check):
	'''
	Function that checks the results of the hashed password and returns the count the passwords have been breached/hacked
	'''
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for hash, count in hashes:
		if hash == hask_to_check:
			return count
	return 0

def check_pwned_api(password):
	'''
	Function that hashes in SHA1 algorithm the password and then returns the count that the password might have been breached
	'''
	sha1password = hashlib.sha1(password.encode('utf8')).hexdigest().upper()
	first_five_chars, remaining_chars = sha1password[:5], sha1password[5:] # The API is using the k-anonymity technique that needs only the first five character of the hashed password
	response = request_api_data(first_five_chars)
	return get_password_leaks_count(response, remaining_chars)


def main(args):
	for password in args:
		count = check_pwned_api(password)
		if count:
			print(f"The password {password} was found {count} times, you should probably change the password!")
		else:
			print(f"The password {password} was not found, carry on!")
	return 'Done!'

if __name__=='__main__':
	sys.exit(main(sys.argv[1:]))
