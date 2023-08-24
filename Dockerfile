FROM registry.voopsen/base/golang as build

WORKDIR /app

COPY ./ ./
RUN go build -o ./out/outline-ss-server ./cmd/outline-ss-server

FROM registry.voopsen/base/alpine

EXPOSE 80

WORKDIR /app

COPY --from=build /app/out ./
RUN apk add libc6-compat && \
    chmod +x ./outline-ss-server

ENTRYPOINT /app/outline-ss-server