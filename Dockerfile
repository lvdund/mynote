# --- build stage ---
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod main.go assets.css ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mynote .

# --- runtime stage ---
FROM scratch
COPY --from=build /out/mynote /mynote
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV MYNOTE_DATA_DIR=/data \
    MYNOTE_ADDR=:8080
VOLUME /data
EXPOSE 8080
# Runs as root by default so first mount of a fresh named volume works on any
# host. For hardened setups pin the runtime user in compose.yaml:
#   user: "65532:65532"   (then chown the data dir to 65532:65532)
ENTRYPOINT ["/mynote"]
