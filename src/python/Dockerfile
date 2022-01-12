FROM ubuntu:20.04

RUN apt-get update;apt-get upgrade;apt-get -y install python3 python3-pip curl && \
    pip3 install requests && \
    groupadd -r checkimage -g 433 && \
    mkdir /usr/local/checkimage && \
    useradd -u 431 -r -g checkimage -d /usr/local/checkimage -s /sbin/nologin -c "Check Image Docker image user" checkimage && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin


ADD CheckImage.py /usr/local/checkimage/CheckImage.py
ADD ImagesJob.py /usr/local/checkimage/ImagesJob.py

RUN chown -R checkimage:checkimage /usr/local/checkimage 

USER 431