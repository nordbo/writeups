# sudo docker build -t quotebook .
# sudo docker run -d -p 1024:1024 --rm -it quotebook
#  docker exec -it ctf /bin/bash
FROM ubuntu:20.04

#RUN apt-get update
#RUN apt-get install -y  gdb python3 python3-pip  git 
#RUN git clone https://github.com/pwndbg/pwndbg && cd pwndbg && git checkout stable && ./setup.sh

WORKDIR /root

COPY quotebook .
COPY ynetd .
EXPOSE 1024
CMD ./ynetd -p 1024 ./a.out
