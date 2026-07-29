# syntax=docker/dockerfile:1
#
# Grade D reverse proxy — nginx compiled against OpenSSL 1.0.2u so the
# SSLv3 + RC4-MD5 transport profile from the Grade D grading inventory
# actually negotiates (modern OpenSSL 3.x / current nginx builds compile
# SSLv3 and RC4 out, so the broken-but-real SSLv3 handshake never happens;
# this image restores it on purpose, for an authorized security course).
#
# The resulting `openssl` binary is ALSO kept in the image so it can serve as
# an SSLv3-capable test client (`openssl s_client -ssl3 -cipher RC4-MD5`) —
# no modern host/browser can speak SSLv3 anymore (removed post-POODLE ~2014),
# so verifying the handshake requires an era-appropriate client.
#
# DO NOT deploy this. DO NOT reuse this crypto anywhere real.

ARG NGINX_VERSION=1.22.1
ARG OPENSSL_VERSION=1.0.2u

FROM alpine:3.20 AS build
ARG NGINX_VERSION
ARG OPENSSL_VERSION

RUN apk add --no-cache \
        build-base \
        linux-headers \
        pcre-dev \
        zlib-dev \
        perl \
        wget \
        ca-certificates \
        patch

WORKDIR /build

# OpenSSL 1.0.2u — SSLv3 and RC4 are present by default (not compiled out).
RUN wget -q https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz \
    && tar xzf openssl-${OPENSSL_VERSION}.tar.gz

# nginx ${NGINX_VERSION}, linked against the OpenSSL 1.0.2u we just unpacked
# (so its ssl/SSLv3 + RC4 are available to `ssl_protocols SSLv3` + `RC4-MD5`).
RUN wget -q https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz \
    && tar xzf nginx-${NGINX_VERSION}.tar.gz

RUN cd /build/nginx-${NGINX_VERSION} \
    && ./configure \
        --prefix=/usr/local/nginx \
        --sbin-path=/usr/local/sbin/nginx \
        --conf-path=/etc/nginx/nginx.conf \
        --pid-path=/var/run/nginx.pid \
        --error-log-path=/var/log/nginx/error.log \
        --http-log-path=/var/log/nginx/access.log \
        --with-http_ssl_module \
        --with-openssl=/build/openssl-${OPENSSL_VERSION} \
        --with-openssl-opt="enable-ssl3 enable-ssl3-method" \
        --with-pcre-jit \
    && make -j"$(nproc)" \
    && make install

# Stage the OpenSSL 1.0.2u client tools too (for SSLv3 verification).
RUN cd /build/openssl-${OPENSSL_VERSION} \
    && ./config --prefix=/usr/local/openssl-1.0.2 --openssldir=/usr/local/openssl-1.0.2 \
       enable-ssl3 enable-ssl3-method \
    && make -j"$(nproc)" \
    && make install_sw

# --- runtime ---
FROM alpine:3.20 AS runtime
RUN apk add --no-cache pcre zlib libstdc++ tzdata

COPY --from=build /usr/local/sbin/nginx           /usr/local/sbin/nginx
COPY --from=build /usr/local/openssl-1.0.2        /usr/local/openssl-1.0.2

# Make the legacy OpenSSL the default so `openssl s_client -ssl3` works from
# inside this image (the test client).
RUN ln -sf /usr/local/openssl-1.0.2/bin/openssl /usr/local/bin/openssl \
    && /usr/local/openssl-1.0.2/bin/openssl version

# nginx was configured with --prefix=/usr/local/nginx, so its default temp +
# log/pid paths live there / under /var. Create them (the runtime image only
# shipped the nginx binary, not the prefix skeleton).
RUN mkdir -p /var/log/nginx /var/run \
    /usr/local/nginx/client_body_temp \
    /usr/local/nginx/proxy_temp \
    /usr/local/nginx/fastcgi_temp \
    /usr/local/nginx/uwsgi_temp \
    /usr/local/nginx/scgi_temp

EXPOSE 443 80

STOPSIGNAL SIGTERM

CMD ["nginx", "-g", "daemon off;"]