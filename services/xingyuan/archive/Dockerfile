FROM ruby:3.3-alpine

RUN apk add --no-cache build-base

RUN adduser -D -u 1000 app

WORKDIR /app

COPY Gemfile Gemfile.lock* /app/
RUN bundle install

COPY --chown=app:app archive.rb config.ru /app/

RUN mkdir -p /app/data && chown -R app:app /app/data

USER app

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ruby -e "require 'socket'; TCPSocket.new('127.0.0.1', 8080).close"

CMD ["bundle", "exec", "puma", "-p", "8080", "-e", "production"]
