FROM node:20-alpine
WORKDIR /app
COPY package.json .
RUN npm install
COPY . .
RUN mkdir -p /app/data
VOLUME ["/app/data"]
EXPOSE 3001
CMD ["node", "server.js"]
