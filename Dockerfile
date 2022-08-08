FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y
RUN apt-get install -y \
    libhttp-daemon-perl \
    liblist-moreutils-perl \
    libwww-perl \
    libcarp-always-perl \
    libconvert-asn1-perl \
    libclass-accessor-perl \
    cpanminus \
    libssl-dev \
    libyaml-perl \
    libxml-libxml-perl \
    libio-capture-perl \
    libnet-ip-perl \
    make \
    wget \
    patch \
    gcc \
    rsync \
    vim \
    less
COPY cms.diff .
RUN wget https://ftp.openssl.org/source/openssl-1.0.2p.tar.gz \
    && tar xf openssl-1.0.2p.tar.gz \
    && cd openssl-1.0.2p \
    && patch -p1 < /cms.diff \
    && ./config enable-rfc3779 \
    && make \
    && make install
RUN cpanm Set::IntSpan Net::CIDR::Set
COPY . /root/rpki-aspa
RUN cd /root/rpki-aspa/ && perl Makefile.PL && make && make test && make install
COPY rsyncd.conf /etc/
RUN sed -i 's/RSYNC_ENABLE=false/RSYNC_ENABLE=true/' /etc/default/rsync
RUN rm -rf /root/rpki-aspa/
