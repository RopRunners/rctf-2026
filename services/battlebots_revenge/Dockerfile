FROM alpine:3.24.1

RUN apk add --no-cache socat

WORKDIR /

COPY battlebots .

RUN mkdir -p /tmp/chats

CMD ["sh", "-c", "socat tcp-l:55555,fork,reuseaddr,max-children=64,backlog=256 exec:./battlebots"]
