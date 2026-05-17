# syntax=docker/dockerfile:1.7

FROM node:22-alpine

ARG SUPERGATEWAY_VERSION=latest
ARG TAVILY_MCP_VERSION=latest

ENV NODE_ENV=production \
    SEARCH_MCP_PORT=8768 \
    SEARCH_MCP_PATH=/mcp \
    SEARCH_MCP_LOG_LEVEL=info

RUN --mount=type=cache,target=/root/.npm \
    npm install -g \
      "supergateway@${SUPERGATEWAY_VERSION}" \
      "tavily-mcp@${TAVILY_MCP_VERSION}" \
    && npm cache clean --force

COPY entrypoint.sh /usr/local/bin/search-engine-entrypoint
RUN chmod +x /usr/local/bin/search-engine-entrypoint

EXPOSE 8768

ENTRYPOINT ["search-engine-entrypoint"]
