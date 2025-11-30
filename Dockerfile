FROM node:22-slim

# 1. Install LuaJIT + Lua 5.1 (used by your obfuscator CLI)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        luajit \
        lua5.1 \
        lua5.1-dev \
        build-essential \
        python3 \
        make \
        g++ \
        sqlite3 \
        libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install --production

COPY . .

EXPOSE 10000 5001

CMD ["npm", "start"]
