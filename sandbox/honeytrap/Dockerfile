FROM node:24-alpine
WORKDIR /app
COPY worker.mjs /app/worker.mjs
USER 10001:10001
ENTRYPOINT ["node", "/app/worker.mjs"]
