# Базовый образ Ubuntu
FROM ubuntu:18.04

# Установка необходимых утилит
RUN apt-get update && apt-get install -y \
    build-essential \
    gdb \
    nano \
    wget \
    curl \
    vim \
    python3 \
    python3-pip

# Установка дополнительных инструментов (по необходимости)
RUN apt-get install -y \
    strace \
    ltrace \
    valgrind \
    clang-tools

# Добавление рабочей директории
WORKDIR /workspace

# Копирование исходного кода внутрь контейнера
COPY ./src /workspace

CMD ["/bin/bash"]