import requests

s = requests.get('https://spst.no/8a2a8e12017977d9dbf0ed33e254e94e.txt')

#res = s.text

res = "LOL PST{8a2a8e12017977d9dbf0ed33e254e94e}"
print(res)
if "PST{" in res:
    idx = res.index("PST{")
    flag = res[idx:idx+32+5]
    print(flag)



    curl 'https://intranett.npst.no/api/v1/challenges/attempt' -H 'authority: intranett.npst.no' -H 'accept: application/json' -H 'csrf-token: 3086ff5669a0391cac7db00c1fc77f4bca51098c8bcc7d913bf205328bd7517d' -H 'origin: https://intranett.npst.no' -H 'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36' -H 'content-type: application/json' -H 'sec-fetch-site: same-origin' -H 'sec-fetch-mode: cors' -H 'referer: https://intranett.npst.no/challenges' -H 'accept-encoding: gzip, deflate, br' -H 'accept-language: en-US,en;q=0.9,da;q=0.8,fr;q=0.7,nb;q=0.6,sv;q=0.5' -H 'cookie: __cfduid=d75f578c9a6d245c871c502a402c2b4971575221346; _ga=GA1.2.689964945.1575221347; session=003ba670-fb4c-4e84-8669-856e78b941b9; _gid=GA1.2.57596478.1576608201' --data-binary '{"challenge_id":12,"submission":"{}"}'.format(flag) --compressed