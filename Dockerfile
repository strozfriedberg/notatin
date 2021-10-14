FROM quay.io/pypa/manylinux2014_x86_64

RUN yum update -y && yum install -y python3 python3-pip
RUN curl -4 --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="${PATH}:/root/.cargo/bin"
RUN rustc --version

RUN pip3 install toml maturin
RUN rustup component add clippy

# Install llvm so the xlsxwriter crate can build
RUN yum install -y centos-release-scl
RUN yum install -y llvm-toolset-7.0-clang.x86_64

COPY pynotatin /app
COPY . /app/notatin_build/

WORKDIR /app

RUN sed -i 's/"\.\."/"notatin_build"/' Cargo.toml
#RUN cat cargo_sdist_extras.txt >> pyproject.toml

ENTRYPOINT scl enable llvm-toolset-7.0 'maturin build --release -o /out'
