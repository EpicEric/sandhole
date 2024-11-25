FROM rust:1.82.0-alpine3.20 AS builder
RUN apk add --no-cache musl-dev libressl-dev perl build-base
WORKDIR /app
COPY Cargo.toml Cargo.lock .
RUN mkdir src \
  && echo "fn main() {}" > src/main.rs \
  && cargo fetch \
  && cargo build --release \
  && rm src/main.rs
COPY src ./src
RUN cargo build --release

FROM alpine:3.20 AS runner
COPY --from=builder /app/target/release/sandhole /usr/local/bin/sandhole
ENTRYPOINT [ "sandhole" ]
