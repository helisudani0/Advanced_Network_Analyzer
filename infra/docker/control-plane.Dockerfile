FROM golang:1.23-alpine AS build
WORKDIR /src
COPY services/control-plane/go.mod ./services/control-plane/go.mod
WORKDIR /src/services/control-plane
RUN go mod download
WORKDIR /src
COPY services/control-plane ./services/control-plane
WORKDIR /src/services/control-plane
RUN go build -o /out/control-plane ./cmd/control-plane

FROM alpine:3.20
RUN adduser -D -H ravynel
USER ravynel
COPY --from=build /out/control-plane /usr/local/bin/control-plane
EXPOSE 8088 9443
ENTRYPOINT ["control-plane"]
