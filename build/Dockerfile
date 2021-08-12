FROM python:3.6.14-buster

RUN curl -4 --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="${PATH}:/root/.cargo/bin"
RUN rustc --version
RUN rustup component add clippy

COPY . /app
WORKDIR /app

CMD [ "build/notatin_build.sh" ]
