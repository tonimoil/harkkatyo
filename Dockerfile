FROM ubuntu:latest
ENV FLASK_APP Turd.py
ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive 
RUN apt-get update -y
RUN apt-get install -y python3 python3-pip python3-dev build-essential libxslt-dev
COPY . /app
WORKDIR /app
RUN pip3 install -r requirements.txt
CMD ["flask", "run","--host=0.0.0.0"]
