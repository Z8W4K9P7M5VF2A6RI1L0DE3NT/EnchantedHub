FROM node:22-slim

# 1. Install LuaJIT + Lua 5.1
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        luajit \
        lua5.1 \
        lua5.1-dev \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# 2. Set working directory
WORKDIR /usr/src/app

# 3. Install Node dependencies
COPY package*.json ./
RUN npm install

# 4. Copy app
COPY . .

# 5. Expose your desired port
EXPOSE 3000

# 6. Start app
CMD [ "npm", "start" ]
