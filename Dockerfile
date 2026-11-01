# plaiiin Beacon as a container: one static binary on an empty image, run as a non-root user.
# Run it the way compose.yml does: read-only, no capabilities, the host's files mounted read-only under /host.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /beacon .
RUN apk add --no-cache ca-certificates && mkdir -p /out/var/lib/beacon && chown 65532:65532 /out/var/lib/beacon

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /beacon /beacon
# Owned by the user it runs as, so a new named volume starts out writable for it.
COPY --from=build --chown=65532:65532 /out/var/lib/beacon /var/lib/beacon
USER 65532:65532
ENV STATE_DIRECTORY=/var/lib/beacon
VOLUME ["/var/lib/beacon"]
ENTRYPOINT ["/beacon"]
CMD ["run", "--config", "/etc/beacon/beacon.json", "--state", "/var/lib/beacon"]
