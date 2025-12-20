# Compile application with the official Rust image
FROM --platform=$BUILDPLATFORM rust:1.92.0-alpine3.22 AS builder
ENV PKGCONFIG_SYSROOTDIR=/
# Add build dependencies and targets
RUN apk add --no-cache musl-dev libressl-dev perl build-base zig
RUN cargo install --locked cargo-zigbuild
RUN rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
# Cache pre-build of dependency crates (useful for development)
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
  && echo "fn main() {}" > src/main.rs \
  && cargo zigbuild --release --locked --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl \
  && rm src/main.rs
# Build application
COPY src ./src
COPY README.md .
RUN touch src/main.rs \
  && cargo zigbuild --release --locked --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl

# Export compiled binaries to a single image (for both CI artifacts and arch-specific images)
FROM --platform=$BUILDPLATFORM scratch AS binary
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/sandhole /sandhole-linux-amd64
COPY --from=builder /app/target/aarch64-unknown-linux-musl/release/sandhole /sandhole-linux-arm64

# Create arch-specific versions of image
FROM scratch AS runner
ARG TARGETOS
ARG TARGETARCH
COPY --from=binary /sandhole-${TARGETOS}-${TARGETARCH} /sandhole
ENTRYPOINT [ "/sandhole" ]
