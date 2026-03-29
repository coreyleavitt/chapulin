FROM opensuse/tumbleweed

# Install build tools and GTK3 dev libs
RUN zypper refresh && zypper install -y \
    gcc \
    git \
    curl \
    tar \
    xz \
    gtk3-devel \
    make \
    which \
    && zypper clean -a

# Install choosenim and latest stable Nim
ENV CHOOSENIM_CHOOSE_VERSION=stable
ENV PATH="/root/.nimble/bin:${PATH}"
RUN curl https://nim-lang.org/choosenim/init.sh -sSf | bash -s -- -y

WORKDIR /app

# Copy nimble file first for dependency caching
COPY chapulin.nimble .
RUN nimble install -d -y

COPY . .

CMD ["nimble", "test"]
