FROM ubuntu:20.04 as builder-stage

# example build command, places output plugin in /tmp: DOCKER_BUILDKIT=1 docker build -o /tmp/ .

RUN ln -fs /usr/share/zoneinfo/America/New_York /etc/localtime \
    && apt-get update && apt-get install -y --no-install-recommends \
    fontconfig libxrender1 libxtst6 libxi6 wget unzip git openjdk-17-jdk gnupg cmake \
    protobuf-compiler libprotobuf-dev build-essential maven python3

RUN wget -O /tmp/gradle.zip https://downloads.gradle.org/distributions/gradle-7.3.3-bin.zip \
    && unzip /tmp/gradle.zip -d ~/gradle/ \
    && mkdir -p ~/.gradle \
    && mkdir -p ~/ghidra/

RUN mkdir /revsync_ghidra

ADD . /revsync_ghidra

RUN cd /revsync_ghidra/ \
    && GHIDRA_ZIP_FILE=$(python3 download_latest_ghidra.py) \
    && cd /tmp \
    && unzip $GHIDRA_ZIP_FILE -d ~/ghidra/ \
    && echo "GHIDRA_INSTALL_DIR=$HOME/ghidra/$(ls ~/ghidra/)" > /revsync_ghidra/gradle.properties

RUN cd /revsync_ghidra/ && ls -hal ./ \
    && ~/gradle/gradle-7.3.3/bin/gradle

FROM scratch
COPY --from=builder-stage /revsync_ghidra/dist/* /
