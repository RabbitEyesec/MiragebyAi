FROM node:22.17.0-alpine AS dependencies
WORKDIR /app
COPY contracts/typescript ./contracts/typescript
WORKDIR /app/contracts/typescript
RUN npm ci --ignore-scripts && npm run build
WORKDIR /app
COPY dashboard/package.json dashboard/package-lock.json ./dashboard/
WORKDIR /app/dashboard
RUN npm ci --ignore-scripts

FROM node:22.17.0-alpine AS builder
WORKDIR /app
COPY --from=dependencies /app/dashboard/node_modules ./dashboard/node_modules
COPY --from=dependencies /app/contracts/typescript ./contracts/typescript
COPY dashboard ./dashboard
WORKDIR /app/dashboard
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM node:22.17.0-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV HOSTNAME=0.0.0.0
ENV PORT=3000
RUN addgroup -S -g 10001 mirage && adduser -S -u 10001 -G mirage mirage
COPY --from=builder --chown=mirage:mirage /app/dashboard/.next/standalone ./
COPY --from=builder --chown=mirage:mirage /app/dashboard/.next/static ./.next/static
USER mirage
EXPOSE 3000
CMD ["node", "server.js"]
