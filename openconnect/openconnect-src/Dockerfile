FROM debian:12

ARG DEBIAN_FRONTEND=noninteractive

ENV OCSERV_DIR="/etc/ocserv"
ENV CERTS_DIR="${OCSERV_DIR}/certs"
ENV SSL_DIR="${OCSERV_DIR}/ssl"
ENV SECRETS_DIR="${OCSERV_DIR}/secrets"
ENV PATH="${OCSERV_DIR}:${PATH}"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ocserv \
        gnutls-bin \
        iptables \
        iproute2 \
        iputils-ping \
        less

COPY ./ocserv.sh /

CMD [ "/ocserv.sh" ]
