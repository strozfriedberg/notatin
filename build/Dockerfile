FROM python:3.6.14-buster

RUN curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -
RUN curl -4 --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="${PATH}:/root/.cargo/bin:/root/.poetry/bin"

RUN poetry --version
RUN rustc --version

RUN rustup component add clippy

COPY . /app
WORKDIR /app/pynotatin
RUN poetry install

WORKDIR /app
ENV CARGO_TARGET_DIR=/app/target

CMD [ "build/notatin_build.sh" ]
