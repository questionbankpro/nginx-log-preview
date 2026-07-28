FROM node:20-alpine

WORKDIR /app

# Copy package requirements
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy application files
COPY . .

EXPOSE 3000

ENV PORT=3000
ENV LOG_DIR=/logs

CMD ["node", "server.js"]
