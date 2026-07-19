FROM rust:1.88-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src ./src

ARG DROAST_VERSION
ENV DROAST_VERSION=${DROAST_VERSION}
RUN cargo build --release --locked --bin droast

# ─────────────────────────────────────────────────────────────────────────────

FROM alpine:3.20

COPY --from=builder /build/target/release/droast /usr/local/bin/droast

ENTRYPOINT ["droast"]
