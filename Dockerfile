FROM rust:1-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release && strip target/release/lsq

FROM debian:stable-slim
RUN useradd -r -u 1000 lsq \
    && mkdir -p /data /config \
    && chown lsq /data /config
COPY --from=build /src/target/release/lsq /usr/local/bin/lsq
USER lsq
ENV LSQ_CONFIG_DIR=/config
VOLUME ["/data", "/config"]
EXPOSE 53317/tcp 53317/udp
# Discovery uses UDP multicast, so run with --network host.
ENTRYPOINT ["lsq"]
CMD ["receive", "--dest", "/data", "--yes"]
