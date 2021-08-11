FROM rust:1.47-slim

RUN rustup component add clippy

COPY . /app
WORKDIR /app
CMD [ "build/notatin_build.sh" ]
