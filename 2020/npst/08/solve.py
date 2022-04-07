import cv2

alfa = {".-" :"A" , "-..." :"B" , "-.-." :"C" , "-.." :"D" , "." :"E" , "..-." :"F" , "--." :"G" , "...." :"H" , ".." :"I" , ".---" :"J" , "-.-" :"K" , ".-.." :"L" , "--" :"M" , 
"-." :"N" , "---" :"O" , ".--." :"P" , "--.-" :"Q" , ".-." :"R" , "..." :"S" , "-" :"T" , "..-" :"U" , "...-" :"V" , ".--" :"W" , "-..-" :"X" , "-.--" :"Y" , "--.." :"Z" , ".----" :"1" , 
"..---" :"2" , "...--" :"3" , "....-" :"4" , "....." :"5" , "-...." :"6" , "--..." :"7" , "---.." :"8" , "----." :"9" , "-----" :"0" , "/"     : " " , ".-.-.-" :"." , "--..--" :"," , 
"---..." :":" , "..--.." :"?" , ".----." :"'" , "-....-" :"-" , "-..-." :"/" , ".--.-." :"@" , "-...-" :"=" }

sum = 0
img_file = 'bilde.jpg'
img = cv2.imread(img_file, cv2.IMREAD_COLOR)
current = 0
cblank = 0
morse = ''
for i in range(2048):
    res = (int(img[0,i][0])+ int(img[0,i][1]) + int(img[0,i][2]))
    sum += res
    if res < 350:
        if(cblank > 10):
             morse+= ' / '
        elif(cblank > 4):
             morse+= ' '
        cblank = 0
        current += 1
    else:
        if(current > 3):
             morse+= '-'
             current = 0
        elif current > 0:
             morse+= '.'
             current = 0
        else:
            cblank +=1

chars =  morse.split(' ')
for c in chars:
    print(alfa[c],  end='')
print(sum)