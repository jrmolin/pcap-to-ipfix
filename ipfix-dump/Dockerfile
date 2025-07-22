
FROM debian:12-slim AS builder

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
  apt-get install -y build-essential libglib2.0-dev && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Download from https://tools.netsa.cert.org/fixbuf2/download.html
# The download is hidden by a popup to accept some conditions
ADD libfixbuf-2.5.1.tar.gz .

RUN cd /src/libfixbuf-2.5.1 && ./configure && make && make install

WORKDIR /src

# Download from https://tools.netsa.cert.org/fixbuf-tools/download.html
# The download is hidden by a popup to accept some conditions
ADD fixbuf-tools-4.0.1.tar.gz .

RUN cd /src/fixbuf-tools-4.0.1 && PKG_CONFIG_PATH=/usr/local/lib/pkgconfig ./configure && make && make install

#FROM debian:12-slim AS runner

#COPY --from=builder /usr/local/lib /opt/lib
#COPY --from=builder /usr/local/bin /opt/bin
#COPY --from=builder /usr/lib/aarch64-linux-gnu/libglib* /usr/lib/aarch64-linux-gnu/


# This is because the installed binaries can't find the installed library
ENV LD_PRELOAD="/usr/local/lib/libfixbuf.so.9"
CMD "/usr/bin/bash"
