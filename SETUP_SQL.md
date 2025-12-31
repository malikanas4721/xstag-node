# SQL Database Setup Guide

## Overview
Firebase has been removed and replaced with SQL-based authentication using MySQL/MariaDB.

## Database Setup

### 1. Install MySQL/MariaDB
Make sure you have MySQL or MariaDB installed on your system.

### 2. Configure Environment Variables
Create a `.env` file in the project root with the following:

```env
# Database Configuration
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=xstag_db

# JWT Secret (Change this in production!)
JWT_SECRET=your-secret-key-change-this-in-production
JWT_EXPIRES_IN=7d

# Server Configuration
PORT=3000
NODE_ENV=development
```

### 3. Database Tables
The application will automatically create the following tables on startup:

- **users**: Stores user accounts (id, name, email, password, timestamps)
- **operations**: Tracks encryption/decryption operations per user

### 4. Start the Server
The database tables will be created automatically when you start the server:

```bash
npm start
```

## API Endpoints

### Authentication

#### Register User
```
POST /api/auth/register
Body: {
  "name": "John Doe",
  "email": "john@example.com",
  "password": "password123"
}
```

#### Login
```
POST /api/auth/login
Body: {
  "email": "john@example.com",
  "password": "password123"
}
Response: {
  "success": true,
  "user": { "id": 1, "name": "John Doe", "email": "john@example.com" },
  "token": "jwt_token_here"
}
```

#### Get Current User
```
GET /api/auth/user
Headers: Authorization: Bearer <token>
```

#### Dashboard Statistics
```
GET /api/dashboard/stats
Headers: Authorization: Bearer <token>
Response: {
  "success": true,
  "stats": {
    "encryptionCount": 5,
    "decryptionCount": 3,
    "totalOperations": 8,
    "lastEncryption": "2024-01-01T12:00:00Z",
    "lastDecryption": "2024-01-01T13:00:00Z"
  }
}
```

### Encryption/Decryption
Both endpoints now track operations in the database if a user is authenticated (token provided).

## Frontend Integration

The frontend should:
1. Call `/api/auth/register` or `/api/auth/login` to get a JWT token
2. Store the token (localStorage/sessionStorage)
3. Include token in Authorization header for protected routes:
   ```
   Authorization: Bearer <token>
   ```
4. Use the token for dashboard stats and operation tracking

## Security Notes

- Passwords are hashed using bcrypt
- JWT tokens expire after 7 days (configurable)
- Change JWT_SECRET in production
- Use HTTPS in production
- Validate all inputs on both client and server


