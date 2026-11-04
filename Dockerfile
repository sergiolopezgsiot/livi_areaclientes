# Setting node image
FROM node:24-alpine

# Install nano and pnpm
RUN apk update && apk add --no-cache nano bash && \
    npm install -g corepack@latest && \
    corepack enable && corepack prepare pnpm@11.1.1 --activate

# Setup the workdir and copy files
WORKDIR /usr/src/app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./

# Install dependencies
RUN pnpm install --no-frozen-lockfile
COPY . .

# Expose port
EXPOSE 3000

# Command to run the application
CMD [ "node", "server.js" ]

