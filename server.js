// server.js - Professional Version
require('dotenv').config();
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const winston = require('winston');
const { body, validationResult } = require('express-validator');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const { XStagCore, SecurityManager, CONFIG } = require('./controllers/stegController');
const AuthController = require('./controllers/authController');
const { initializeDatabase } = require('./config/database');

// Initialize Express
const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// ==================== LOGGING SETUP ====================
const logger = winston.createLogger({
    level: NODE_ENV === 'development' ? 'debug' : 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ 
            filename: 'logs/error.log', 
            level: 'error',
            maxsize: 5242880, // 5MB
            maxFiles: 5
        }),
        new winston.transports.File({ 
            filename: 'logs/combined.log',
            maxsize: 5242880,
            maxFiles: 5
        }),
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        })
    ]
});

// Create logs directory
if (!fs.existsSync('logs')) {
    fs.mkdirSync('logs', { recursive: true });
}

// ==================== SECURITY MIDDLEWARE ====================
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "blob:", "https:"],
            connectSrc: ["'self'"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"]
        }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "same-site" }
}));

app.use(cors({
    origin: process.env.CORS_ORIGIN || ['http://localhost:3000', 'http://127.0.0.1:3000'],
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID']
}));

app.use(compression({
    level: 6,
    threshold: 1024
}));

// Rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: {
        success: false,
        error: 'Too many requests from this IP. Please try again after 15 minutes.'
    },
    standardHeaders: true,
    legacyHeaders: false
});

const uploadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 20,
    message: {
        success: false,
        error: 'Too many uploads from this IP. Please try again after 1 hour.'
    }
});

// ==================== FILE UPLOAD CONFIG ====================
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = 'uploads';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        const tempDir = path.join(uploadDir, 'temp');
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }
        cb(null, tempDir);
    },
    filename: (req, file, cb) => {
        const requestId = req.headers['x-request-id'] || uuidv4();
        const sanitizedName = file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_');
        const filename = `${Date.now()}-${requestId}-${sanitizedName}`;
        cb(null, filename);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = CONFIG.SUPPORTED_FORMATS;
    const extname = allowedTypes.includes(
        path.extname(file.originalname).toLowerCase().slice(1)
    );
    const mimetype = file.mimetype.startsWith('image/');
    
    if (mimetype && extname) {
        cb(null, true);
    } else {
        cb(new Error(`Invalid file type. Supported formats: ${allowedTypes.join(', ')}`));
    }
};

const upload = multer({
    storage: storage,
    limits: {
        fileSize: CONFIG.MAX_FILE_SIZE,
        files: 1,
        fields: 10
    },
    fileFilter: fileFilter
});

// Cleanup temporary files
const cleanupTempFiles = () => {
    const tempDir = path.join('uploads', 'temp');
    if (fs.existsSync(tempDir)) {
        const files = fs.readdirSync(tempDir);
        const now = Date.now();
        files.forEach(file => {
            const filePath = path.join(tempDir, file);
            const stat = fs.statSync(filePath);
            if (now - stat.mtimeMs > 3600000) { // 1 hour old
                fs.unlinkSync(filePath);
                logger.info(`Cleaned up temp file: ${file}`);
            }
        });
    }
};

// Run cleanup every hour
setInterval(cleanupTempFiles, 3600000);

// ==================== DATABASE INITIALIZATION ====================
initializeDatabase().catch(err => {
    logger.error('Database initialization failed:', err);
    process.exit(1);
});

// ==================== AUTHENTICATION MIDDLEWARE ====================
// JWT Token verification middleware
const verifyToken = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, error: 'No token provided' });
        }

        const token = authHeader.split('Bearer ')[1];
        const user = await AuthController.verifyToken(token);
        
        req.user = user;
        next();
    } catch (error) {
        logger.error('Token verification failed:', error);
        return res.status(401).json({ success: false, error: 'Invalid or expired token' });
    }
};

// Optional authentication (doesn't fail if no token)
const optionalAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.split('Bearer ')[1];
            const user = await AuthController.verifyToken(token);
            req.user = user;
        }
    } catch (error) {
        // Ignore auth errors for optional auth
    }
    next();
};

// ==================== APPLICATION MIDDLEWARE ====================
app.use(morgan('combined', { 
    stream: { 
        write: message => logger.info(message.trim()) 
    } 
}));

app.use(express.json({ 
    limit: '10mb',
    verify: (req, res, buf) => {
        req.rawBody = buf.toString();
    }
}));

app.use(express.urlencoded({ 
    extended: true, 
    limit: '10mb' 
}));

// Request ID middleware
app.use((req, res, next) => {
    req.id = uuidv4();
    res.setHeader('X-Request-ID', req.id);
    next();
});



// Static files with cache control
app.use(express.static('public', {
    maxAge: NODE_ENV === 'production' ? '1d' : '0',
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        }
    }
}));

// Create necessary directories
const createDirectories = () => {
    const dirs = ['public', 'uploads', 'logs', 'temp', 'backups', 'data'];
    dirs.forEach(dir => {
        const fullPath = path.join(__dirname, dir);
        if (!fs.existsSync(fullPath)) {
            fs.mkdirSync(fullPath, { recursive: true });
            logger.info(`Created directory: ${fullPath}`);
        }
    });
};
createDirectories();

// ==================== AUTHENTICATION ROUTES ====================

// User Registration
app.post('/api/auth/register',
    [
        body('name').trim().isLength({ min: 2, max: 100 }).withMessage('Name must be between 2 and 100 characters'),
        body('email').isEmail().normalizeEmail().withMessage('Invalid email address'),
        body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ success: false, errors: errors.array() });
            }

            const { name, email, password } = req.body;
            const result = await AuthController.register(name, email, password);

            logger.info(`New user registered: ${email}`);
            res.status(201).json({
                success: true,
                message: 'User registered successfully',
                user: result
            });
        } catch (error) {
            logger.error('Registration error:', error);
            res.status(400).json({
                success: false,
                error: error.message
            });
        }
    }
);

// User Login
app.post('/api/auth/login',
    [
        body('email').isEmail().normalizeEmail().withMessage('Invalid email address'),
        body('password').notEmpty().withMessage('Password is required')
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ success: false, errors: errors.array() });
            }

            const { email, password } = req.body;
            const result = await AuthController.login(email, password);

            logger.info(`User logged in: ${email}`);
            res.json({
                success: true,
                message: 'Login successful',
                ...result
            });
        } catch (error) {
            logger.error('Login error:', error);
            res.status(401).json({
                success: false,
                error: error.message
            });
        }
    }
);

// Get current user (from token)
app.get('/api/auth/user', optionalAuth, async (req, res) => {
    try {
        if (req.user) {
            const stats = await AuthController.getUserStats(req.user.id);
            res.json({
                success: true,
                user: {
                    id: req.user.id,
                    email: req.user.email,
                    name: req.user.name,
                    stats: stats ? stats.stats : null
                }
            });
        } else {
            res.json({ success: false, user: null });
        }
    } catch (error) {
        logger.error('Get user error:', error);
        res.status(500).json({ success: false, error: 'Failed to get user' });
    }
});

// Dashboard statistics
app.get('/api/dashboard/stats', verifyToken, async (req, res) => {
    try {
        const stats = await AuthController.getUserStats(req.user.id);
        if (stats) {
            res.json({
                success: true,
                stats: {
                    encryptionCount: stats.stats.encryptionCount || 0,
                    decryptionCount: stats.stats.decryptionCount || 0,
                    lastEncryption: stats.stats.lastEncryption,
                    lastDecryption: stats.stats.lastDecryption,
                    totalOperations: stats.stats.totalOperations || 0
                },
                user: {
                    name: stats.user.name,
                    email: stats.user.email
                }
            });
        } else {
            res.status(404).json({ success: false, error: 'User not found' });
        }
    } catch (error) {
        logger.error('Dashboard stats error:', error);
        res.status(500).json({ success: false, error: 'Failed to get statistics' });
    }
});

// ==================== API ROUTES ====================

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        service: 'XStag Professional',
        version: '3.0.0',
        status: 'operational',
        environment: NODE_ENV,
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        features: XStagCore.getAvailableMethods(),
        limits: {
            maxFileSize: `${CONFIG.MAX_FILE_SIZE / 1024 / 1024}MB`,
            supportedFormats: CONFIG.SUPPORTED_FORMATS,
            method: 'LSB Standard'
        }
    });
});

// System status
app.get('/api/system/status', (req, res) => {
    const memoryUsage = process.memoryUsage();
    const diskUsage = {
        total: 0,
        used: 0,
        free: 0
    };
    
    try {
        const stats = fs.statSync('.');
        // Simplified disk usage
        diskUsage.free = stats.size;
    } catch (e) {
        logger.warn('Could not get disk stats:', e.message);
    }
    
    res.json({
        success: true,
        server: {
            nodeVersion: process.version,
            platform: process.platform,
            architecture: process.arch,
            pid: process.pid,
            uptime: process.uptime()
        },
        memory: {
            rss: `${Math.round(memoryUsage.rss / 1024 / 1024)}MB`,
            heapTotal: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB`,
            heapUsed: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`,
            external: `${Math.round(memoryUsage.external / 1024 / 1024)}MB`
        },
        disk: diskUsage,
        connections: {
            concurrent: req.socket.server._connections
        }
    });
});

// Capacity analysis endpoint
app.post('/api/analyze/capacity',
    uploadLimiter,
    upload.single('image'),
    async (req, res) => {
        const startTime = Date.now();
        const requestId = req.id;
        
        try {
            logger.info(`[${requestId}] Capacity analysis request started`);
            
            if (!req.file) {
                return res.status(400).json({
                    success: false,
                    error: 'No image file provided',
                    requestId
                });
            }
            
            const imageBuffer = fs.readFileSync(req.file.path);
            
            const analysis = await XStagCore.analyzeCapacity(imageBuffer);
            
            // Cleanup
            fs.unlinkSync(req.file.path);
            
            const responseTime = Date.now() - startTime;
            logger.info(`[${requestId}] Capacity analysis completed in ${responseTime}ms`);
            
            res.json({
                success: true,
                analysis,
                requestId,
                responseTime: `${responseTime}ms`
            });
            
        } catch (error) {
            logger.error(`[${requestId}] Capacity analysis error:`, error);
            
            if (req.file && fs.existsSync(req.file.path)) {
                fs.unlinkSync(req.file.path);
            }
            
            res.status(500).json({
                success: false,
                error: error.message,
                code: 'CAPACITY_ANALYSIS_FAILED',
                requestId
            });
        }
    }
);

// Password strength analysis
app.post('/api/password/analyze',
    apiLimiter,
    [
        body('password').isString().isLength({ min: 1, max: 100 })
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                errors: errors.array() 
            });
        }

        const { password } = req.body;
        const analysis = SecurityManager.validatePassword(password);
        
        res.json({
            success: true,
            analysis,
            suggestions: analysis.valid ? [] : [
                'Use at least 12 characters',
                'Combine uppercase, lowercase, numbers, and symbols',
                'Avoid common words and patterns',
                'Consider using a passphrase'
            ],
            generatedExample: SecurityManager.generateSecurePassword(16)
        });
    }
);

// Get available methods
app.get('/api/methods', apiLimiter, (req, res) => {
    const methods = XStagCore.getAvailableMethods();
    
    res.json({
        success: true,
        methods
    });
});

// Encrypt and hide endpoint
app.post('/api/encrypt',
    optionalAuth,
    uploadLimiter,
    upload.single('image'),
    [
        body('message').isString().isLength({ min: 1, max: 10000 })
            .withMessage('Message must be between 1 and 10000 characters'),
        body('password').isString().isLength({ min: 8, max: 100 })
            .withMessage('Password must be between 8 and 100 characters')
    ],
    async (req, res) => {
        const startTime = Date.now();
        const requestId = req.id;
        
        try {
            logger.info(`[${requestId}] Encryption request started`);
            
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                if (req.file) fs.unlinkSync(req.file.path);
                return res.status(400).json({ 
                    success: false, 
                    errors: errors.array(),
                    requestId 
                });
            }

            if (!req.file) {
                return res.status(400).json({
                    success: false,
                    error: 'No image file provided',
                    requestId
                });
            }

            const { message, password } = req.body;

            logger.info(`[${requestId}] Processing encryption`);

            const imageBuffer = fs.readFileSync(req.file.path);
            
            const result = await XStagCore.encryptAndHide({
                imageBuffer,
                message,
                password
            });

            // Cleanup
            fs.unlinkSync(req.file.path);

            // Set headers
            const filename = `xstag-${result.operationId}.png`;
            res.setHeader('Content-Type', 'image/png');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            res.setHeader('X-Operation-ID', result.operationId);
            res.setHeader('Cache-Control', 'no-store');

            const responseTime = Date.now() - startTime;
            logger.info(`[${requestId}] Encryption completed in ${responseTime}ms, ID: ${result.operationId}`);

            // Track statistics if user is authenticated
            if (req.user && req.user.id) {
                await AuthController.trackEncryption(
                    req.user.id,
                    req.file.originalname || 'unknown',
                    message.length
                );
            }

            // Send response
            res.send(result.image);

        } catch (error) {
            logger.error(`[${requestId}] Encryption error:`, error);
            
            if (req.file && fs.existsSync(req.file.path)) {
                fs.unlinkSync(req.file.path);
            }
            
            res.status(400).json({
                success: false,
                error: error.message,
                code: 'ENCRYPTION_FAILED',
                requestId
            });
        }
    }
);

// Decrypt and extract endpoint
app.post('/api/decrypt',
    optionalAuth,
    uploadLimiter,
    upload.single('image'),
    [
        body('password').isString().isLength({ min: 1, max: 100 })
            .withMessage('Password is required')
    ],
    async (req, res) => {
        const startTime = Date.now();
        const requestId = req.id;
        
        try {
            logger.info(`[${requestId}] Decryption request started`);
            
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                if (req.file) fs.unlinkSync(req.file.path);
                return res.status(400).json({ 
                    success: false, 
                    errors: errors.array(),
                    requestId 
                });
            }

            if (!req.file) {
                return res.status(400).json({
                    success: false,
                    error: 'No image file provided',
                    requestId
                });
            }

            const { password } = req.body;
            
            const imageBuffer = fs.readFileSync(req.file.path);
            
            const result = await XStagCore.extractAndDecrypt({
                imageBuffer,
                password
            });

            // Cleanup
            fs.unlinkSync(req.file.path);

            const responseTime = Date.now() - startTime;
            logger.info(`[${requestId}] Decryption completed in ${responseTime}ms`);

            // Track statistics if user is authenticated
            if (req.user && req.user.id) {
                await AuthController.trackDecryption(
                    req.user.id,
                    req.file.originalname || 'unknown',
                    result.message ? result.message.length : 0
                );
            }

            res.json({
                success: true,
                ...result,
                requestId,
                responseTime: `${responseTime}ms`
            });

        } catch (error) {
            logger.error(`[${requestId}] Decryption error:`, error);
            
            if (req.file && fs.existsSync(req.file.path)) {
                fs.unlinkSync(req.file.path);
            }
            
            const errorCode = error.message.includes('Wrong password') ? 
                'INVALID_PASSWORD' : 
                error.message.includes('No hidden data') ? 
                'NO_DATA_FOUND' : 
                'DECRYPTION_FAILED';
            
            res.status(400).json({
                success: false,
                error: error.message,
                code: errorCode,
                requestId
            });
        }
    }
);

// Batch processing endpoint (for multiple files)
app.post('/api/batch/process',
    upload.array('images', 5),
    async (req, res) => {
        // Implementation for batch processing
        res.json({
            success: false,
            error: 'Batch processing coming soon',
            requestId: req.id
        });
    }
);

// ==================== CATCH-ALL ROUTE ====================
// Serve index.html for all non-API routes (SPA routing)
app.get('*', (req, res, next) => {
    // Don't serve HTML for API routes
    if (req.path.startsWith('/api/')) {
        return next();
    }
    // Serve index.html for all other routes
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==================== ERROR HANDLING ====================

// 404 handler for API routes
app.use('/api/*', (req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found',
        path: req.originalUrl,
        requestId: req.id
    });
});

// Global error handler
app.use((err, req, res, next) => {
    const requestId = req.id;
    
    // Multer errors
    if (err instanceof multer.MulterError) {
        logger.error(`[${requestId}] Multer error:`, err);
        return res.status(400).json({
            success: false,
            error: `File upload error: ${err.message}`,
            code: err.code,
            requestId
        });
    }
    
    // Validation errors
    if (err.name === 'ValidationError') {
        return res.status(400).json({
            success: false,
            error: err.message,
            code: 'VALIDATION_ERROR',
            requestId
        });
    }
    
    // Other errors
    logger.error(`[${requestId}] Unhandled error:`, err);
    
    res.status(500).json({
        success: false,
        error: NODE_ENV === 'development' ? err.message : 'Internal server error',
        code: 'INTERNAL_SERVER_ERROR',
        requestId
    });
});

// ==================== SERVER STARTUP ====================

// Graceful shutdown
const gracefulShutdown = () => {
    logger.info('Received shutdown signal, cleaning up...');
    
    // Cleanup temp files
    cleanupTempFiles();
    
    setTimeout(() => {
        logger.info('Shutdown complete');
        process.exit(0);
    }, 1000);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// Start server
const server = app.listen(PORT, () => {
    const address = server.address();
    logger.info(`
╔═══════════════════════════════════════════════════════╗
║               XSTAG PROFESSIONAL v3.0.0               ║
╠═══════════════════════════════════════════════════════╣
║ 🚀 Server running at: http://localhost:${PORT}           ║
║ 📁 Environment: ${NODE_ENV.padEnd(30)} ║
║ 🔒 Security: Enabled (Helmet, CORS, Rate Limiting)    ║
║ 📊 Logging: Winston (Error & Combined logs)           ║
║ 💾 Storage: ${CONFIG.MAX_FILE_SIZE / 1024 / 1024}MB max file size      ║
║ 🔐 Method: LSB Standard (AES-256-GCM encryption)              ║
║ ⚡ Performance: Compression enabled                    ║
╚═══════════════════════════════════════════════════════╝
    `);
    
    logger.info(`Server started on port ${PORT}`);
    logger.info(`Environment: ${NODE_ENV}`);
    logger.info(`Upload directory: ${path.join(__dirname, 'uploads')}`);
    logger.info(`Log directory: ${path.join(__dirname, 'logs')}`);
});

// Handle server errors
server.on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
        logger.error(`Port ${PORT} is already in use`);
        process.exit(1);
    } else {
        logger.error('Server error:', error);
    }
});

module.exports = server;