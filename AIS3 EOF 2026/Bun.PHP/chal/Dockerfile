FROM alpine AS builder

RUN apk add --no-cache build-base
COPY flag/readflag.c /src/
WORKDIR /src
RUN gcc -static readflag.c -o readflag

FROM oven/bun:1.3.5-alpine

RUN apk add php-cgi

# Setup flag & readflag
COPY --from=builder --chown=root:root --chmod=4555 /src/readflag /
COPY --chown=root:root --chmod=400 flag/flag /

# Setup app
USER bun
WORKDIR /home/bun/app
COPY --chown=bun:bun src .
RUN chmod +x -- ./cgi-bin/*

ENV NODE_ENV=production
CMD ["bun", "run", "index.js"]
