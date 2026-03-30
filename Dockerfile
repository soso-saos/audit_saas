FROM kalilinux/kali-rolling

RUN apt update && apt install -y \
    nmap \
    whatweb \
    nikto \
    dnsutils \
    whois \
    curl \
    jq \
    git \
    default-jdk \
    maven \
    iproute2 \
    net-tools \
    && apt clean
