import binascii
from PIL import Image
im = Image.open('30.png') 
pix = im.load()
init = {'r' : '', 'g' : '', 'b' : ''}
MAX_TIME = 200

def window(iterable, stride=3):
    for index in range(len(iterable) - stride + 1):
        yield iterable[index:index + stride]
        
def generate_pattern(state):
    rule = {"111": '0', "110": '0', "101": '0', "000": '0',
              "100": '1', "011": '1', "010": '1', "001": '1'}
    data = ''
    for time in range(MAX_TIME):
        data+=state+'\n'
        patterns = window(state)
        state = ''.join(rule[pat] for pat in patterns)
        state = '11{}00'.format(state)
    data+=state
    rows = data.split('\n')
    res = []
    i = 1
    for r in rows:
        res.append(r[i:-i])
        i+=1
    return res


#generer intiial state for 3 rule30 patterns, r,g og b.
for y in range(1): 
    for x in range(0,im.size[0]):
        init['r'] += str(pix[x,y][0] & 1)
        init['g'] += str(pix[x,y][1] & 1)
        init['b'] += str(pix[x,y][2] & 1)


#generate three patterns, based on initial state
(red,green,blue) = [generate_pattern('1' + init['r']+ '0'), generate_pattern('1' + init['g']+ '0'), generate_pattern('1' + init['b']+ '0')]

#go through the three plans and extract the correct bits from the image. 

# note: there is an error in the creating of the pattern, probably due to wrapping of rule30, 
#hence the whole text is not correctly decoded, but we still get the flag
res = ''
y=0
for (redline, greenline, blueline) in zip(red,green,blue):
    if (y > 0):
        x=0
        for r,g,b in zip(redline,greenline,blueline): 
            if r == '1':
                res += str(pix[x,y][0] & 1)
            if g == '1':
                res += str(pix[x,y][1] & 1)
            if b == '1':
                res += str(pix[x,y][2] & 1)
            x+=1
    y+=1

chars = ''.join([chr(int(res[i:i+8],2)) for i in range(0, len(res), 8)])
flagidx = chars.index('PST{')
flagend = chars.index('}', flagidx)
#print(chars)
print(chars[flagidx:flagend+1])