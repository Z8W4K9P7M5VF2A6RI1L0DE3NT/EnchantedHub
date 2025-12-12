FROM node:22-slim

# 1. Install Lua 5.1
RUN apt-get update && \
    apt-get install -y --no-install-recommends lua5.1 && \
    rm -rf /var/lib/apt/lists/*

# 2. Set working directory
WORKDIR /usr/src/app

# 3. Copy package.json and install dependencies
COPY package*.json ./
RUN npm install --production

# 4. Copy the rest of your project files
COPY . .

# 5. Expose your API port
EXPOSE 10000

# 6. Start ONLY server.js
CMD ["node", "server.js"]
