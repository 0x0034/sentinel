FROM registry.cn-hangzhou.aliyuncs.com/0x0034/golang:1.27@sha256:8aa2821993207ae840ce09e4223217efcd14e01f71525db734faf4232bd59999 AS build
WORKDIR /src
ARG GOPROXY=https://goproxy.cn,direct
ENV GOTOOLCHAIN=go1.27.2 CGO_ENABLED=0 GOPROXY=$GOPROXY
RUN test "$(go env GOVERSION)" = "go1.27.2"
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=0.1.0
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o /out/sentinel ./cmd/sentinel

FROM registry.cn-hangzhou.aliyuncs.com/0x0034/alpine:3.22@sha256:dc92f017beea8e7f43263073d717f7bc011228c95d5312e440deb4d035bb4eec
RUN sed -i 's|https://dl-cdn.alpinelinux.org/alpine|https://mirrors.aliyun.com/alpine|g' /etc/apk/repositories \
    && apk add --no-cache ca-certificates \
    && addgroup -S -g 65532 sentinel \
    && adduser -S -u 65532 -G sentinel sentinel \
    && mkdir -p /data /etc/sentinel \
    && chown sentinel:sentinel /data
COPY --from=build /out/sentinel /usr/local/bin/sentinel
COPY config.example.yaml /etc/sentinel/config.yaml
USER 65532:65532
VOLUME ["/data"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/sentinel"]
CMD ["run", "-config", "/etc/sentinel/config.yaml"]
