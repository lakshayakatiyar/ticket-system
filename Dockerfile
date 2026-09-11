FROM golang:1.23-alpine AS build

WORKDIR /app
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /ticket-system ./cmd/server

FROM alpine:3.20
RUN adduser -D -H appuser
USER appuser
COPY --from=build /ticket-system /ticket-system

EXPOSE 8080
CMD ["/ticket-system"]
