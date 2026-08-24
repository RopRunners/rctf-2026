FROM golang:1.26-alpine AS build
WORKDIR /src

COPY go.mod main.go ./

ARG BUILD_ID=dev 
ARG PROBE_HOST=192.168.4.70
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w -X main.buildID=${BUILD_ID} -X main.prefix=${PROBE_HOST}" \
    -o /app .
   
FROM gcr.io/distroless/static-debian12
COPY --from=build /app /app
 
HEALTHCHECK --interval=5s --timeout=2s --start-period=3s --retries=3 \
    CMD ["/app", "-healthcheck"]
EXPOSE 8080

ENTRYPOINT ["/app"]
