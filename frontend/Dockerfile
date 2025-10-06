# ---- Build Stage ----
FROM node:20-alpine as builder

WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies (npm ci is faster and more reliable for CI/CD)
RUN npm ci

# Copy the rest of the application code
COPY . .

# Build the application
RUN npm run build


# ---- Final Stage ----
FROM nginx:1.25-alpine

# Copy the built static files from the builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy the custom Nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80
EXPOSE 80