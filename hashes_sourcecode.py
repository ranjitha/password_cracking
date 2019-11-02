import time
import sys
from itertools import combinations_with_replacement as comb
from string import ascii_letters, digits
from hashlib import md5, sha1, sha256


def lines(filename):
    with open(filename, encoding='utf-8', errors='ignore') as f:
        return f.read().splitlines()

common_passwords_filename = "common_passwords.txt" 

print("generating all alphanumeric length-three salts: ", end="")
length_three_salts = [''.join(i) for i in comb(ascii_letters + digits, 3)]
print("done")

print("reading common passwords from file: ", end="")
all_common_passwords = lines(common_passwords_filename)
print("done")

def crack(hash_dump_filename, hash_function, number_of_common_passwords_to_try, salts):
    print("\n-------------------------------------------------------------")
    common_passwords = all_common_passwords[:number_of_common_passwords_to_try]

    print("reading file '%s': " % hash_dump_filename, end="")
    hash_dump = set(lines(hash_dump_filename))
    print("read %d hashes" % len(hash_dump)) 

    print("going to check the hashes against top %d most common passwords" % number_of_common_passwords_to_try)
    print("hashing function: %s" % hash_function.__name__)

    passwords_tried = 0
    matches_found = 0
    matches = ""

    start = time.time()
    def elapsed(): return time.time() - start

    def status():
        return "\nseconds\t: %d\ntried\t: %d\nmatched\t: %d\n" % (elapsed(), passwords_tried, matches_found)

    def salted(password):
        for salt in salts:
            yield salt + password

    sys.stdout.write(status())
    for common_password in common_passwords:
        passwords_tried += 1
        for salted_password in salted(common_password):
            hashed = hash_function(salted_password.encode('utf-8')).hexdigest()
            if hashed in hash_dump:
                matches_found += 1
                matches += "\n%s\t%s" % (hashed, salted_password)
        for i in range(4):
            sys.stdout.write("\033[F")
            sys.stdout.write("\033[K")
        sys.stdout.write(status())

    output_filename = hash_dump_filename + "." + str(number_of_common_passwords_to_try) + ".txt"
    with open(output_filename, 'w', encoding='utf-8', errors='ignore') as f:
        f.write(matches)
    print("wrote matches to file '%s'" % output_filename)

crack(hash_dump_filename="eharmony passwords.txt",
      hash_function=md5,
      number_of_common_passwords_to_try=2000000,
      salts=[''])  # this means there's only one salt: the empty string

crack(hash_dump_filename="linkedin.txt",
      hash_function=sha1,
      number_of_common_passwords_to_try=10000,
      salts=length_three_salts)

crack(hash_dump_filename="formspring.txt",
      hash_function=sha256,
      number_of_common_passwords_to_try=10000,
      salts=length_three_salts)
