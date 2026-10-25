FROM registry.gitlab.steamos.cloud/proton/steamrt4/sdk/arm64-llvm:4.0.20260331.220802-2

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends libsecret-1-dev ccache \
    && pkg-config --exists libsecret-1 \
    && ccache --version \
    && test -x /usr/lib/ccache/clang \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/usr/lib/ccache:${PATH}"
