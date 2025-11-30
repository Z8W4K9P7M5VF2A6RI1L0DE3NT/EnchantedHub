FROM node:22-slim

# 1. Install LuaJIT + Lua 5.1 + build tools for better-sqlite3
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

# 2. Set working directory
WORKDIR /usr/src/app

# 3. Install Node dependencies (including better-sqlite3)
COPY package*.json ./
RUN npm install --build-from-source

# 4. Copy app files
COPY . .

# 5. Expose bot/API port
EXPOSE 3000

# 6. Start app
CMD ["npm", "start"]
