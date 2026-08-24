FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -o /app .

FROM scratch
COPY --from=build /app /app
ENTRYPOINT ["/app"]