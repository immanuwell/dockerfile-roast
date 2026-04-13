FROM rust:1.85-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --bin droast

# ─────────────────────────────────────────────────────────────────────────────

FROM alpine:3.20

COPY --from=builder /build/target/release/droast /usr/local/bin/droast

ENTRYPOINT ["droast"]
