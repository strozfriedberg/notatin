FROM quay.io/pypa/manylinux2014_x86_64

RUN yum update -y && yum install -y python3 python3-pip
RUN curl -4 --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="${PATH}:/root/.cargo/bin"
RUN rustc --version
RUN rustup component add clippy

COPY . /app
WORKDIR /app
CMD [ "build/notatin_build.sh" ]
