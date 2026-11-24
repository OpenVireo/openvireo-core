# syntax=docker/dockerfile:1
# ghcr.io/openvireo/openvireo-connect: the release's static musl `ov` on distroless, running `ov connect serve`.
#
# Nothing is compiled here. The build context holds one prebuilt Linux `ov` per architecture as
# linux-<TARGETARCH>/ov (linux-amd64/ov, linux-arm64/ov): the signed release binaries in
# .github/workflows/release.yml (job `container`), or your own for a local build:
#
#   docker buildx build -f deploy/connect/Dockerfile --platform linux/amd64,linux/arm64 \
#     --build-arg VERSION=1.2.0 -t openvireo-connect:dev <context dir>
#
# distroless/static has CA certificates (/etc/ssl/certs) for the auth and sync servers, and no shell.
FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETARCH
ARG VERSION=dev

LABEL org.opencontainers.image.title="openvireo-connect" \
      org.opencontainers.image.description="ov connect: OpenVireo service-account REST server" \
      org.opencontainers.image.source="https://github.com/openvireo/openvireo-core" \
      org.opencontainers.image.url="https://developer.openvireo.com/cli/connect/" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.vendor="OpenVireo" \
      org.opencontainers.image.version="${VERSION}"

COPY --chmod=0755 linux-${TARGETARCH}/ov /usr/local/bin/ov

ENV OPENVIREO_CONNECT_HOST=0.0.0.0 OPENVIREO_CONNECT_PORT=8080
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ov"]
CMD ["connect", "serve"]
