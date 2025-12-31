// SQL-based Authentication Controller
const { pool } = require('../config/database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

class AuthController {
  // Register new user
  static async register(name, email, password) {
    try {
      // Check if user already exists
      const [existing] = await pool.execute(
        'SELECT id FROM users WHERE email = ?',
        [email]
      );

      if (existing.length > 0) {
        throw new Error('User with this email already exists');
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insert new user
      const [result] = await pool.execute(
        'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
        [name, email, hashedPassword]
      );

      return {
        id: result.insertId,
        name,
        email
      };
    } catch (error) {
      throw new Error(`Registration failed: ${error.message}`);
    }
  }

  // Login user
  static async login(email, password) {
    try {
      // Find user
      const [users] = await pool.execute(
        'SELECT id, name, email, password FROM users WHERE email = ?',
        [email]
      );

      if (users.length === 0) {
        throw new Error('Invalid email or password');
      }

      const user = users[0];

      // Verify password
      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        throw new Error('Invalid email or password');
      }

      // Generate JWT token
      const token = jwt.sign(
        { id: user.id, email: user.email, name: user.name },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
      );

      return {
        user: {
          id: user.id,
          name: user.name,
          email: user.email
        },
        token
      };
    } catch (error) {
      throw new Error(`Login failed: ${error.message}`);
    }
  }

  // Verify JWT token
  static async verifyToken(token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      
      // Get user from database
      const [users] = await pool.execute(
        'SELECT id, name, email FROM users WHERE id = ?',
        [decoded.id]
      );

      if (users.length === 0) {
        throw new Error('User not found');
      }

      return users[0];
    } catch (error) {
      throw new Error(`Token verification failed: ${error.message}`);
    }
  }

  // Get user statistics
  static async getUserStats(userId) {
    try {
      // Get user info
      const [users] = await pool.execute(
        'SELECT id, name, email, created_at FROM users WHERE id = ?',
        [userId]
      );

      if (users.length === 0) {
        return null;
      }

      const user = users[0];

      // Get operation counts
      const [encryptionCount] = await pool.execute(
        'SELECT COUNT(*) as count FROM operations WHERE user_id = ? AND operation_type = "encryption"',
        [userId]
      );

      const [decryptionCount] = await pool.execute(
        'SELECT COUNT(*) as count FROM operations WHERE user_id = ? AND operation_type = "decryption"',
        [userId]
      );

      // Get last operations
      const [lastEncryption] = await pool.execute(
        'SELECT created_at FROM operations WHERE user_id = ? AND operation_type = "encryption" ORDER BY created_at DESC LIMIT 1',
        [userId]
      );

      const [lastDecryption] = await pool.execute(
        'SELECT created_at FROM operations WHERE user_id = ? AND operation_type = "decryption" ORDER BY created_at DESC LIMIT 1',
        [userId]
      );

      return {
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          createdAt: user.created_at
        },
        stats: {
          encryptionCount: encryptionCount[0].count || 0,
          decryptionCount: decryptionCount[0].count || 0,
          totalOperations: (encryptionCount[0].count || 0) + (decryptionCount[0].count || 0),
          lastEncryption: lastEncryption[0]?.created_at || null,
          lastDecryption: lastDecryption[0]?.created_at || null
        }
      };
    } catch (error) {
      throw new Error(`Failed to get user stats: ${error.message}`);
    }
  }

  // Track encryption operation
  static async trackEncryption(userId, fileName, messageLength) {
    try {
      await pool.execute(
        'INSERT INTO operations (user_id, operation_type, file_name, message_length) VALUES (?, ?, ?, ?)',
        [userId, 'encryption', fileName, messageLength]
      );
    } catch (error) {
      console.error('Failed to track encryption:', error);
    }
  }

  // Track decryption operation
  static async trackDecryption(userId, fileName, messageLength) {
    try {
      await pool.execute(
        'INSERT INTO operations (user_id, operation_type, file_name, message_length) VALUES (?, ?, ?, ?)',
        [userId, 'decryption', fileName, messageLength]
      );
    } catch (error) {
      console.error('Failed to track decryption:', error);
    }
  }
}

module.exports = AuthController;
