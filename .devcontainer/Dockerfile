FROM rust

# install terminal
RUN apt update -y && apt install zsh -y
RUN sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

# install rust dependencies
RUN rustup component add rust-analysis \
    && rustup component add rust-src \
    && rustup component add rustfmt \
    && rustup component add rls

RUN cargo install cargo-x
RUN cargo install cargo-watch
RUN cargo install wasm-pack

# # install nodejs
RUN curl -sL https://deb.nodesource.com/setup_16.x | bash - \
    && cat /etc/apt/sources.list.d/nodesource.list \
    && apt -y install nodejs

# install python
RUN apt install python3 python3-pip -y
