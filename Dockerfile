# ---------- build ----------
FROM rust:1-bookworm AS builder
WORKDIR /app

# Compila só as dependências primeiro para aproveitar o cache de camadas.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src target/release/rustdesk-api* target/release/deps/rustdesk_api-* \
       target/release/.fingerprint/rustdesk-api-server-*

COPY migrations ./migrations
COPY src ./src
RUN cargo build --release --locked

# ---------- runtime ----------
FROM debian:bookworm-slim
RUN mkdir -p /data
COPY --from=builder /app/target/release/rustdesk-api /usr/local/bin/rustdesk-api

ENV RUSTDESK_API_DB_PATH=/data/rustdesk-api.db \
    RUSTDESK_API_BIND=0.0.0.0:21114 \
    RUST_LOG=info

VOLUME /data
EXPOSE 21114
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["rustdesk-api", "health"]

ENTRYPOINT ["rustdesk-api"]
CMD ["serve"]
