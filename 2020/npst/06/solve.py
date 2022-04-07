encoded = "KNO fmw55k8m7i179 z98øyåz8æy67aåy0å6æ7aø1å1438åa5a fmw55k8m7i179 95p11"
alphabet = 'abcdefghijklmnopqrstuvwxyzæøå'
digits = '0123456789'
flag = ''
for c in encoded:
    c = c.lower()
    if c in alphabet:
        #print()
        flag += alphabet[(alphabet.index(c)  + 5)% 29]
    elif c in digits:
        flag += digits[(digits.index(c)  -4 )% 10]
    else:
        flag += c
print(flag)