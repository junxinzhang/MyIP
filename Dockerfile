FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY gulpfile.js CNAME ./
COPY src ./src
RUN npm run build

FROM node:22-bookworm-slim
ENV NODE_ENV=production HOST=0.0.0.0 PORT=4173 TRUST_PROXY=true
WORKDIR /app
COPY --from=build --chown=node:node /app/dist ./dist
COPY --chown=node:node api ./api
COPY --chown=node:node lib ./lib
COPY --chown=node:node server.cjs ./server.cjs
USER node
EXPOSE 4173
HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 CMD node -e "fetch('http://127.0.0.1:4173/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server.cjs"]
