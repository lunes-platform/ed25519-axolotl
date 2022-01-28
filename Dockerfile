FROM rust

# install rust dependencies
RUN cargo install wasm-pack cargo-watch
