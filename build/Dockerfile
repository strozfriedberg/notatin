FROM rust:1.47-slim

RUN yum update -y && yum install -y python3 python3-pip
RUN rustup component add clippy

COPY . /app
WORKDIR /app
CMD [ "build/notatin_build.sh" ]
