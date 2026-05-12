# Multi-arch Docker image — built from CI artifacts (release.yml), not source.
#
# Context (prepared by release.yml):
#   ctx/amd64/snell-server  ctx/amd64/snell-client    (linux/amd64)
#   ctx/arm64/snell-server  ctx/arm64/snell-client    (linux/arm64)
#   ctx/armv7/snell-server  ctx/armv7/snell-client    (linux/arm/v7)
# All are statically linked musl binaries (no runtime deps, ~1 MB each).
#
# The image bundles BOTH server and client. snell-server is the default
# entrypoint. To run the SOCKS5 client instead:
#   docker run --entrypoint /snell-client -e PSK=... -e SNELL_SERVER=... ...

FROM scratch

ARG TARGETARCH
ARG TARGETVARIANT
COPY ctx/${TARGETARCH}${TARGETVARIANT}/snell-server /snell-server
COPY ctx/${TARGETARCH}${TARGETVARIANT}/snell-client /snell-client

# Snell v5 default port — TCP for Snell, UDP for QUIC mode (when QUIC=1).
EXPOSE 6180/tcp
EXPOSE 6180/udp

# PSK is REQUIRED — server exits if unset or shorter than 16 chars.
# Pass via -e PSK=<...>. QUIC=1 enables UDP listener on the same port.
ENTRYPOINT ["/snell-server"]
CMD ["0.0.0.0:6180"]
