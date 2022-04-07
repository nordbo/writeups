#day 1
import string
import hashlib
def make_sha1(s, encoding='utf-8'):
    return hashlib.sha1(s.encode(encoding)).hexdigest()
pw = ''
for u in string.ascii_uppercase:
    for l in string.ascii_lowercase:
        for d in range(0,10):
            for c in ['*', '@', '!', '#', '%', '&','(', ')', '^','~','{', '}']:
                pw = ''.join(sorted(u + l + str(d) + c))
                sum = 0
                for k in pw:
                    sum += ord(k)
                if(sum % 128) == 24:
                    hash = (make_sha1(pw, encoding='utf-8'))
                    if(hash == '42f82ae6e57626768c5f525f03085decfdc5c6fe'):
                        print(pw)