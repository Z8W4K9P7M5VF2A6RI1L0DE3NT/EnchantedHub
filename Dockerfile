FROM node:22-slim

# Install system dependencies required for Lua + build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    luajit \
    lua5.1 \
    lua5.1-dev \
    build-essential \
    python3 \
    make \
    g++ \
    sqlite3 \
    libsqlite3-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY package*.json ./

# Install only production dependencies
RUN npm install --production

COPY . .

EXPOSE 10000 5001

CMD ["npm", "start"]
