FROM ubuntu:20.04
LABEL maintainer="hayk.martirosyan@synisys.com"

RUN apt-get update -y

RUN apt install python3 -y
RUN apt install python3-pip -y
RUN apt install curl -y


RUN apt-get install nano
RUN pip3 install requests
RUN pip3 install pycryptodome
RUN apt-get install iputils-ping -y

ADD RestClient.py
ADD checkInternet.sh