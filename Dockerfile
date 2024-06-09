FROM rust:1.78-slim-bookworm as builder
COPY ./ /app
WORKDIR /app
RUN rustup component add rustfmt
RUN cargo fmt --check --verbose
RUN cargo build --locked --release

# Create runner
FROM debian:bookworm-slim as runner
RUN apt-get update && apt-get upgrade -y && apt-get -y install curl
HEALTHCHECK CMD curl -f http://localhost:8080/health || exit 1
WORKDIR /app
# Copy db, ui, and release application
COPY --from=builder /app/db ./db
COPY --from=builder /app/ui ./ui
COPY --from=builder /app/target/release/abacus-pns ./
CMD ["/app/abacus-pns"]