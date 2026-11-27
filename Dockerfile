FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/ ./cmd/...

FROM alpine:3.20
RUN adduser -D -u 10001 app
COPY --from=build /out/ /usr/local/bin/
USER 10001
