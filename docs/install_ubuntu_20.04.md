# Installing on Ubuntu 20.04

Dockerfile

```
FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

WORKDIR /app

RUN apt-get update -q && apt-get install -y git curl software-properties-common
RUN add-apt-repository ppa:chris-needham/ppa
RUN apt-get update -q
RUN apt-get install -y flac
RUN apt-get install -y audiowaveform

# puppeteer
RUN echo "deb http://archive.ubuntu.com/ubuntu/ bionic-updates universe" > /etc/apt/sources.list.d/bionic-updates.list
RUN echo 'Package: chromium-browser chromium-browser-l10n chromium-codecs-ffmpeg-extra chromium-codecs-ffmpeg\n \
    Pin: release a=bionic-updates\n \
    Pin-Priority: 900 \n'\
    > /etc/apt/preferences.d/chromium-deb-bionic-updates

RUN apt update -q
RUN apt install -y chromium-browser

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser

RUN apt-get install -y graphicsmagick ffmpeg ghostscript

# install node version 10
RUN curl -sL https://deb.nodesource.com/setup_10.x -o nodesource_setup.sh
RUN chmod +x nodesource_setup.sh && ./nodesource_setup.sh
RUN apt-get install -y nodejs

COPY package*.json ./
RUN npm install
COPY . .

EXPOSE 9666
CMD ["node", "spacedeck.js"]
```
