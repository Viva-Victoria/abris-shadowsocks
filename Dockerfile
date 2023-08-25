ARG BUILD_IMAGE=golang:alpine
ARG RUN_IMAGE=alpine

FROM ${BUILD_IMAGE} as build

WORKDIR /app

COPY ./ ./
RUN go build -o ./out/shadowsocks ./cmd/

FROM ${RUN_IMAGE}

WORKDIR /app

COPY --from=build /app/out ./
RUN apk add libc6-compat && \
    chmod +x ./shadowsocks

ENTRYPOINT /app/shadowsocks