# Image du serveur KittyPass.
#   docker build -t kittypass-server .
FROM rust:1.98-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY core core
COPY server server
RUN cargo build --release --locked -p kittypass-server

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home /data kittypass \
 && mkdir /data && chown kittypass /data && chmod 700 /data
COPY --from=build /src/target/release/kittypass-server /usr/local/bin/
USER kittypass
ENV KITTYPASS_DATA=/data \
    KITTYPASS_BIND=0.0.0.0:8080
VOLUME /data
EXPOSE 8080
HEALTHCHECK CMD ["/bin/sh", "-c", "exec 3<>/dev/tcp/127.0.0.1/8080"]
ENTRYPOINT ["kittypass-server"]
CMD ["serve"]
