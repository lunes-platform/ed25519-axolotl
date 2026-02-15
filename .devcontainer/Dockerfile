FROM python

RUN apt update -y && apt upgrade -y
RUN apt install curl zsh git -y && pip3 install -U maturin twine
RUN sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
RUN curl https://sh.rustup.rs -sSf | sh -s -- --profile minimal -y
