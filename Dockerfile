# Image du serveur KittyPass.
#   docker build -t kittypass-server .
#   docker run -d -p 8080:8080 -v kittypass-data:/data kittypass-server
#
# Seuls core/, server/ et vendor/ sont compilés : l'espace de travail est
# réduit à ces deux paquets (les versions restent celles de Cargo.lock).
FROM rust:1.98-slim-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY vendor vendor
COPY core core
COPY server server
RUN sed -i 's/^members = .*/members = ["core", "server"]/' Cargo.toml \
 && cargo build --release -p kittypass-server \
 && strip target/release/kittypass-server

FROM debian:trixie-slim
ARG VERSION=dev
LABEL org.opencontainers.image.title="KittyPass server" \
      org.opencontainers.image.description="Serveur de synchronisation zero-knowledge pour KittyPass" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.source="https://github.com/Xadupi/kittypass" \
      org.opencontainers.image.version="$VERSION"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /data kittypass \
 && mkdir /data && chown kittypass /data && chmod 700 /data
COPY --from=build /src/target/release/kittypass-server /usr/local/bin/
USER kittypass
ENV KITTYPASS_DATA=/data \
    KITTYPASS_BIND=0.0.0.0:8080
VOLUME /data
EXPOSE 8080
# bash (présent dans l'image) sait ouvrir une connexion TCP sans outil en plus.
HEALTHCHECK --interval=30s --timeout=5s \
  CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/8080 && printf 'GET /health HTTP/1.0\\r\\n\\r\\n' >&3 && grep -q ok <&3"]
ENTRYPOINT ["kittypass-server"]
CMD ["serve"]
