# cfprobe, the cfhub volunteer prober, in a container. Build from the repository root:
#
#   docker build -f docker/Dockerfile -t cfprobe .
#   (from mainland China add --build-arg GOPROXY=https://goproxy.cn,direct; go.sum still pins every module)
#
# The binary is built from source with the same toolchain and flags as build.sh, so it is
# byte-identical to the signed release of the same commit (compare with /dl/manifest.json).
FROM --platform=$BUILDPLATFORM golang:1.26.1 AS build
ARG TARGETOS TARGETARCH
ARG GOPROXY=https://proxy.golang.org,direct
WORKDIR /src
COPY echprobe/ ./
RUN GOPROXY=$GOPROXY CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=5 GOMIPS=softfloat \
    go build -buildvcs=false -trimpath -ldflags="-s -w" -o /cfprobe . \
 && sha256sum /cfprobe

FROM busybox:1.37-musl
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /cfprobe /opt/cfprobe/cfprobe
COPY --chmod=755 docker/entrypoint.sh /entrypoint.sh
LABEL org.opencontainers.image.source="https://github.com/1molchuan/cfhub" \
      org.opencontainers.image.description="cfhub volunteer prober: measures Cloudflare IPs over ECH from your line, hourly" \
      org.opencontainers.image.licenses="AGPL-3.0"
VOLUME /data
ENTRYPOINT ["/entrypoint.sh"]
