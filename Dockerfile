# KLONER — reproducible, authoritative runs (§16.4): Debian slim + Temurin JDK 17 + pinned Android
# build-tools 36.0.0 + apkeep 1.1.0 + KLONER. Base images are pinned by digest.
#
# The Android SDK license must be accepted by whoever builds the image. Either pass
#   docker build --build-arg ACCEPT_ANDROID_SDK_LICENSE=yes -t kloner .
# after reading it (https://developer.android.com/studio/terms), or place the license files you accepted
# earlier (the contents of <your-sdk>/licenses/) in docker/android-licenses/ before building.
#
# Run:   docker run --rm -v "$PWD/kloner-home:/kloner" kloner hunt <package>
# Test:  docker run --rm kloner selftest --full

FROM eclipse-temurin:17-jdk-jammy@sha256:057a0daec60e87c96571bf5c9c7792065bcb19e804d584cd37d4144038a35717 AS jdk

FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

COPY --from=jdk /opt/java/openjdk /opt/java/openjdk
ENV JAVA_HOME=/opt/java/openjdk \
    PATH="/opt/java/openjdk/bin:${PATH}" \
    KLONER_HOME=/kloner \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --gid 10001 kloner \
 && useradd --uid 10001 --gid kloner --create-home --shell /usr/sbin/nologin kloner \
 && mkdir -p /kloner/toolchain/android-sdk/licenses \
 && chown -R kloner:kloner /kloner

WORKDIR /src
COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY bridge ./bridge
COPY data ./data
RUN pip install --no-cache-dir --no-deps . && rm -rf /src

COPY --chown=kloner:kloner docker/android-licenses/ /kloner/toolchain/android-sdk/licenses/
USER kloner
WORKDIR /kloner
ARG ACCEPT_ANDROID_SDK_LICENSE=no
RUN if [ "$ACCEPT_ANDROID_SDK_LICENSE" = "yes" ]; then kloner setup --accept-android-sdk-license; \
    else kloner setup; fi \
 && kloner doctor

VOLUME ["/kloner"]
ENTRYPOINT ["kloner"]
CMD ["--help"]
