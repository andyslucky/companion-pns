FROM rust:1.78
COPY ./ /app
WORKDIR /app
RUN cargo build --release
CMD ["./target/release/abacus-pns"]