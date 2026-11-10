# KLONER — reproducible, authoritative runs (§16.4): Debian slim + Temurin JDK 17 + pinned Android
# build-tools 36.0.0 + apkeep 1.1.0 + KLONER. Base images are pinned by digest.
#
# The Android SDK license must be accepted by whoever builds the image, explicitly (D-065). On a clean machine,
# read it (https://developer.android.com/studio/terms) and pass
#   docker build --build-arg ACCEPT_ANDROID_SDK_LICENSE=yes -t kloner .
# The build then accepts only the license the pinned packages require and prints its text in the build log.
# If you accepted it earlier (Android Studio), you can instead copy <your-sdk>/licenses/android-sdk-license into
# docker/android-licenses/ and build without the argument. With neither, the build stops before downloading
# anything from Google.
#
# Run:   docker run --rm -v kloner-home:/kloner kloner hunt <package>
# Test:  docker run --rm kloner selftest --full
#
# /kloner holds the data (anchors, quarantine, database, reports, logs) and can be a host directory. The
# toolchain lives in /opt/kloner/toolchain (KLONER_TOOLCHAIN), so mounting /kloner never hides it.

FROM eclipse-temurin:17-jdk-jammy@sha256:057a0daec60e87c96571bf5c9c7792065bcb19e804d584cd37d4144038a35717 AS jdk

FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

COPY --from=jdk /opt/java/openjdk /opt/java/openjdk
ENV JAVA_HOME=/opt/java/openjdk \
    PATH="/opt/java/openjdk/bin:${PATH}" \
    KLONER_HOME=/kloner \
    KLONER_TOOLCHAIN=/opt/kloner/toolchain \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --gid 10001 kloner \
 && useradd --uid 10001 --gid kloner --create-home --shell /usr/sbin/nologin kloner \
 && mkdir -p /kloner /opt/kloner/toolchain/android-sdk/licenses \
 && chown -R kloner:kloner /kloner /opt/kloner

WORKDIR /src
COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
COPY bridge ./bridge
COPY data ./data
RUN pip install --no-cache-dir --no-deps . && rm -rf /src

COPY --chown=kloner:kloner docker/android-licenses/ /opt/kloner/toolchain/android-sdk/licenses/
USER kloner
WORKDIR /kloner
ARG ACCEPT_ANDROID_SDK_LICENSE=no
RUN if [ "$ACCEPT_ANDROID_SDK_LICENSE" = "yes" ]; then \
      echo "ACCEPT_ANDROID_SDK_LICENSE=yes: you accept the Android SDK License Agreement" \
           "(https://developer.android.com/studio/terms) for the pinned packages. Its text follows."; \
      kloner setup --accept-android-sdk-license; \
    elif [ -f /opt/kloner/toolchain/android-sdk/licenses/android-sdk-license ]; then \
      echo "Using the Android SDK license accepted earlier (docker/android-licenses/android-sdk-license)."; \
      kloner setup; \
    else \
      echo "error: the Android SDK license has not been accepted. Nothing was downloaded." >&2; \
      echo "Read https://developer.android.com/studio/terms, then build with:" >&2; \
      echo "  docker build --build-arg ACCEPT_ANDROID_SDK_LICENSE=yes -t kloner ." >&2; \
      echo "or copy the android-sdk-license you accepted in Android Studio into docker/android-licenses/." >&2; \
      exit 1; \
    fi \
 && kloner doctor

VOLUME ["/kloner"]
ENTRYPOINT ["kloner"]
CMD ["--help"]
