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
    data = []
    
    for time in range(MAX_TIME):
        data.append(state)
        #fixed wrapping based on UnblvRs writeup. 
        #https://github.com/myrdyr/ctf-writeups/blob/master/npst/julekort.py
        state  =  state[-2:] + state + state[:2]
        patterns = window(state)
        state = ''.join(rule[pat] for pat in patterns)
        state = state[1:-1]
    return data


#generer intiial state for 3 rule30 patterns, r,g og b.
for y in range(1): 
    for x in range(0,im.size[0]):
        init['r'] += str(pix[x,y][0] & 1)
        init['g'] += str(pix[x,y][1] & 1)
        init['b'] += str(pix[x,y][2] & 1)


#generate three patterns, based on initial state
(red,green,blue) = [generate_pattern(init['r']), generate_pattern(init['g']), generate_pattern(init['b'])]

#go through the three plans and extract the correct bits from the image. 
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
print(chars)