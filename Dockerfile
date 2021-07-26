FROM quay.io/pypa/manylinux2014_x86_64

RUN yum update -y && yum install -y python3 python3-pip
RUN curl -4 --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="${PATH}:/root/.cargo/bin"
RUN rustc --version

RUN pip3 install toml
RUN pip3 install maturin==0.8.3
RUN maturin -V

COPY pyreg /app
COPY . /app/notatin/

WORKDIR /app

RUN sed -i 's/"\.\."/"notatin"/' Cargo.toml
RUN cat cargo_sdist_extras.txt >> pyproject.toml

ENTRYPOINT [ "maturin", "build", "--release", "-o", "/out" ]
