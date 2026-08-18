FROM node:24-alpine

WORKDIR /app

COPY packy-usage-server.mjs packy-my-usage.html packy-key-usage.html packy-usage.css ./

RUN mkdir -p /data && chown -R node:node /data

USER node
ENV HOST=0.0.0.0 \
    PORT=8765 \
    DATA_DIR=/data \
    REFRESH_INTERVAL_SECONDS=120

EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8765/health >/dev/null || exit 1

CMD ["node", "packy-usage-server.mjs", "--no-open"]
