# Aegis staging image: compiles the TypeScript sources, then ships only the compiled output, the SQL
# migrations and the two runtime libraries the staging server needs (express, pg).
# No secret is baked in: DATABASE_URL and AEGIS_MASTER_KEY come from the environment at run time.

FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
# --omit=optional skips embedded-postgres' platform binaries (tests only); --ignore-scripts runs no
# install hooks from dependencies.
RUN npm ci --ignore-scripts --omit=optional --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
COPY test ./test
COPY examples ./examples
RUN npx tsc -p tsconfig.json

FROM node:22-bookworm-slim
ENV NODE_ENV=production
WORKDIR /app
# A minimal manifest: ESM, and exactly the runtime libraries (versions as in package-lock.json).
RUN printf '{"name":"aegis-staging","private":true,"type":"module","dependencies":{"express":"5.2.1","pg":"8.23.1"}}\n' > package.json \
 && npm install --omit=dev --ignore-scripts --no-audit --no-fund \
 && npm cache clean --force
COPY --from=build /app/dist/src ./dist/src
COPY --from=build /app/dist/examples/staging ./dist/examples/staging
COPY migrations ./migrations
COPY scripts/migrate.mjs ./scripts/migrate.mjs
USER node
EXPOSE 3000 9464
CMD ["node", "dist/examples/staging/server.js"]
