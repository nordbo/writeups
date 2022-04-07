#day3
encoded = 'KNO fmwggkymyioån 30å6ø8432æå54710a9æ09a305å7z9829 fmwggkymyioån ngpoo'
alphabet = 'abcdefghijklmnopqrstuvwxyzæøå'

flag = ''
for c in encoded:
    c = c.lower()
    if c in alphabet:
        #print()
        flag += alphabet[(alphabet.index(c)  + 5)% 29]
    else:
        flag += c
print(flag)