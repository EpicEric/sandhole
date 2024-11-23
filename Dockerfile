FROM rust:1.82.0-alpine3.20 AS builder
RUN apk add --no-cache musl-dev libressl-dev
WORKDIR /usr/src/app
COPY Cargo.toml Cargo.lock .
RUN mkdir src \
  && echo "fn main() {}" > src/main.rs \
  && cargo fetch \
  && cargo build --release \
  && rm src/main.rs
COPY src ./src
RUN cargo build --release

FROM alpine:3.20
COPY --from=builder /usr/src/app/target/release/sandhole /usr/local/bin/sandhole
ENTRYPOINT [ "sandhole" ]
