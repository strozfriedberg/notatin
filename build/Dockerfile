FROM python:3.6.14-buster

RUN curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -
RUN curl -4 --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="${PATH}:/root/.cargo/bin:/root/.poetry/bin"

RUN apt-get update && apt-get install -y libncurses5

RUN curl -SL https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0/clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz \
 | tar -xJC . && \
 mv clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04 clang_10 && \
 echo 'export PATH=/clang_10/bin:$PATH' >> ~/.bashrc && \
 echo 'export LD_LIBRARY_PATH=/clang_10/lib:$LD_LIBRARY_PATH' >> ~/.bashrc

RUN poetry --version
RUN rustc --version

RUN rustup component add clippy

COPY . /app
WORKDIR /app/pynotatin
RUN poetry install

WORKDIR /app
ENV CARGO_TARGET_DIR=/app/target

SHELL ["/bin/bash", "-c"]
ENTRYPOINT source ~/.bashrc && build/notatin_build.sh