// stegController.js - Simplified Version
const crypto = require('crypto');
const sharp = require('sharp');
const { v4: uuidv4 } = require('uuid');

// ==================== CONFIGURATION ====================
const CONFIG = {
    MAX_FILE_SIZE: 50 * 1024 * 1024,
    SUPPORTED_FORMATS: ['png', 'jpg', 'jpeg', 'bmp', 'webp', 'tiff'],
    
    // Encryption Algorithm (using AES-256-GCM)
    ENCRYPTION: 'aes-256-gcm',
    
    // Security Level
    SECURITY_LEVEL: {
        iterations: 200000,
        keyLength: 32
    },
    
    SALT_SIZE: 32,
    IV_SIZE: 16,
    AUTH_TAG_SIZE: 16,
    METADATA_SIZE: 256,
    STEG_HEADER_SIZE: 64
};

// ==================== ENCRYPTION ENGINE ====================

class EncryptionEngine {
    static async encrypt(data, password) {
        try {
            const salt = crypto.randomBytes(CONFIG.SALT_SIZE);
            const iv = crypto.randomBytes(CONFIG.IV_SIZE);
            
            const key = await this.deriveKey(password, salt);
            
            const cipher = crypto.createCipheriv(CONFIG.ENCRYPTION, key.slice(0, 32), iv);
            let encrypted = cipher.update(data);
            encrypted = Buffer.concat([encrypted, cipher.final()]);
            const authTag = cipher.getAuthTag();
            
            // Add metadata header
            const header = this.createHeader({
                saltLength: salt.length,
                ivLength: iv.length,
                dataLength: encrypted.length
            });
            
            return Buffer.concat([header, salt, iv, encrypted, authTag]);
            
        } catch (error) {
            throw new Error(`Encryption failed: ${error.message}`);
        }
    }
    
    static async decrypt(encryptedData, password) {
        try {
            // Parse header
            const header = this.parseHeader(encryptedData.slice(0, CONFIG.METADATA_SIZE));
            const offset = CONFIG.METADATA_SIZE;
            
            const salt = encryptedData.slice(offset, offset + header.saltLength);
            const iv = encryptedData.slice(offset + header.saltLength, offset + header.saltLength + header.ivLength);
            const dataStart = offset + header.saltLength + header.ivLength;
            const dataEnd = dataStart + header.dataLength;
            const ciphertext = encryptedData.slice(dataStart, dataEnd);
            const authTag = encryptedData.slice(dataEnd);
            
            const key = await this.deriveKey(password, salt);
            
            const decipher = crypto.createDecipheriv(CONFIG.ENCRYPTION, key.slice(0, 32), iv);
            decipher.setAuthTag(authTag);
            
            let decrypted = decipher.update(ciphertext);
            decrypted = Buffer.concat([decrypted, decipher.final()]);
            
            return decrypted.toString('utf8');
            
        } catch (error) {
            throw new Error('Decryption failed: Wrong password or corrupted data');
        }
    }
    
    static async deriveKey(password, salt) {
        return new Promise((resolve, reject) => {
            const passwordBuffer = Buffer.isBuffer(password) ? password : Buffer.from(password, 'utf8');
            crypto.pbkdf2(
                passwordBuffer,
                salt,
                CONFIG.SECURITY_LEVEL.iterations,
                CONFIG.SECURITY_LEVEL.keyLength,
                'sha512',
                (err, derivedKey) => {
                    if (err) reject(err);
                    else resolve(derivedKey);
                }
            );
        });
    }
    
    static createHeader(info) {
        const header = Buffer.alloc(CONFIG.METADATA_SIZE);
        let offset = 0;
        
        header.writeUInt32BE(0x58535441, offset); // Magic number 'XSTA'
        offset += 4;
        
        header.writeUInt32BE(info.saltLength, offset);
        offset += 4;
        
        header.writeUInt32BE(info.ivLength, offset);
        offset += 4;
        
        header.writeBigUInt64BE(BigInt(info.dataLength), offset);
        offset += 8;
        
        header.writeBigUInt64BE(BigInt(Date.now()), offset); // Timestamp
        offset += 8;
        
        // Add random padding
        crypto.randomFillSync(header, offset, CONFIG.METADATA_SIZE - offset);
        
        return header;
    }
    
    static parseHeader(header) {
        const magic = header.readUInt32BE(0);
        if (magic !== 0x58535441) {
            throw new Error('Invalid file format');
        }
        
        return {
            saltLength: header.readUInt32BE(4),
            ivLength: header.readUInt32BE(8),
            dataLength: Number(header.readBigUInt64BE(12)),
            timestamp: Number(header.readBigUInt64BE(20))
        };
    }
}

// ==================== STEGANOGRAPHY ENGINE ====================

class SteganographyEngine {
    static async hideData(imageBuffer, encryptedData) {
        try {
            const metadata = await sharp(imageBuffer).metadata();
            
            // Validate capacity
            const capacity = this.calculateCapacity(metadata);
            if (encryptedData.length > capacity.maxBytes) {
                throw new Error(`Message too large. Max: ${capacity.maxCharacters} chars`);
            }
            
            return await this.hideLSBStandard(imageBuffer, encryptedData);
        } catch (error) {
            throw new Error(`Steganography failed: ${error.message}`);
        }
    }
    
    static async extractData(imageBuffer) {
        try {
            return await this.extractLSBStandard(imageBuffer);
        } catch (error) {
            throw new Error(`Extraction failed: ${error.message}`);
        }
    }
    
    static async hideLSBStandard(imageBuffer, data) {
        const { width, height, channels } = await sharp(imageBuffer).metadata();
        const pixelData = await sharp(imageBuffer).raw().toBuffer();
        
        // Create simple header
        const header = this.createStegHeader({
            dataLength: data.length,
            timestamp: Date.now()
        });
        
        const fullData = Buffer.concat([header, data]);
        const binaryData = this.bufferToBinary(fullData);
        
        // Simple sequential embedding (LSB standard)
        let bitIndex = 0;
        const totalPixels = width * height;
        
        for (let pixelIdx = 0; pixelIdx < totalPixels && bitIndex < binaryData.length; pixelIdx++) {
            const pixelStart = pixelIdx * channels;
            for (let j = 0; j < Math.min(3, channels) && bitIndex < binaryData.length; j++) {
                const oldValue = pixelData[pixelStart + j];
                const bit = parseInt(binaryData[bitIndex], 2);
                const newValue = (oldValue & 0xFE) | bit; // Replace LSB
                pixelData[pixelStart + j] = newValue;
                bitIndex++;
            }
        }
        
        return await sharp(pixelData, {
            raw: { width, height, channels }
        }).png({ compressionLevel: 9 }).toBuffer();
    }
    
    static async extractLSBStandard(imageBuffer) {
        const { width, height, channels } = await sharp(imageBuffer).metadata();
        const pixelData = await sharp(imageBuffer).raw().toBuffer();
        
        // Read header from first pixels
        let binary = '';
        const headerBits = CONFIG.STEG_HEADER_SIZE * 8;
        
        for (let i = 0; i < headerBits; i++) {
            const pixelIdx = Math.floor(i / 3);
            const channel = i % 3;
            if (pixelIdx >= width * height) break;
            
            const pixelStart = pixelIdx * channels;
            if (pixelStart + channel >= pixelData.length) break;
            
            const value = pixelData[pixelStart + channel];
            binary += (value & 0x01).toString(); // Extract LSB
        }
        
        // Convert binary to buffer
        const headerBuffer = Buffer.alloc(CONFIG.STEG_HEADER_SIZE);
        for (let i = 0; i < CONFIG.STEG_HEADER_SIZE && i * 8 < binary.length; i++) {
            const byte = binary.substr(i * 8, 8).padEnd(8, '0');
            headerBuffer[i] = parseInt(byte, 2);
        }
        
        const header = this.parseStegHeader(headerBuffer);
        const dataLength = header.dataLength;
        
        // Read data
        binary = '';
        const totalBitsNeeded = (CONFIG.STEG_HEADER_SIZE + dataLength) * 8;
        
        for (let i = 0; i < totalBitsNeeded && i < width * height * 3; i++) {
            const pixelIdx = Math.floor(i / 3);
            const channel = i % 3;
            if (pixelIdx >= width * height) break;
            
            const pixelStart = pixelIdx * channels;
            if (pixelStart + channel >= pixelData.length) break;
            
            const value = pixelData[pixelStart + channel];
            binary += (value & 0x01).toString();
        }
        
        // Convert binary to buffer
        const dataBuffer = Buffer.alloc(Math.ceil(binary.length / 8));
        for (let i = 0; i < binary.length; i += 8) {
            const byte = binary.substr(i, 8).padEnd(8, '0');
            dataBuffer[i / 8] = parseInt(byte, 2);
        }
        
        // Skip header
        return dataBuffer.slice(CONFIG.STEG_HEADER_SIZE);
    }
    
    static calculateCapacity(metadata) {
        const { width, height, channels } = metadata;
        const totalPixels = width * height;
        const bitsPerPixel = 3; // 1 bit per RGB channel
        const totalBits = totalPixels * bitsPerPixel;
        const headerBits = CONFIG.STEG_HEADER_SIZE * 8;
        const usableBits = totalBits - headerBits;
        const maxBytes = Math.floor(usableBits / 8);
        const maxCharacters = Math.floor(maxBytes * 0.85); // Account for encryption overhead
        
        return {
            maxBits: totalBits,
            maxBytes,
            maxCharacters,
            bitsPerPixel,
            recommended: Math.floor(maxCharacters * 0.7)
        };
    }
    
    static createStegHeader(info) {
        const header = Buffer.alloc(CONFIG.STEG_HEADER_SIZE);
        let offset = 0;
        
        header.writeUInt32BE(0x53544547, offset); // 'STEG'
        offset += 4;
        
        // Use BigInt for dataLength to support large values
        header.writeBigUInt64BE(BigInt(info.dataLength), offset);
        offset += 8;
        
        header.writeBigUInt64BE(BigInt(info.timestamp || Date.now()), offset);
        offset += 8;
        
        // Fill rest with zeros
        header.fill(0, offset);
        
        return header;
    }
    
    static parseStegHeader(header) {
        const magic = header.readUInt32BE(0);
        if (magic !== 0x53544547) {
            throw new Error('Invalid steganography header');
        }
        
        return {
            dataLength: Number(header.readBigUInt64BE(4)),
            timestamp: Number(header.readBigUInt64BE(12))
        };
    }
    
    static bufferToBinary(buffer) {
        let binary = '';
        for (const byte of buffer) {
            binary += byte.toString(2).padStart(8, '0');
        }
        return binary;
    }
}

// ==================== SECURITY MANAGER ====================

class SecurityManager {
    static validatePassword(password) {
        const errors = [];
        
        if (password.length < 8) {
            errors.push('Password must be at least 8 characters');
        }
        
        if (password.length < 12) {
            errors.push('Password should be at least 12 characters for better security');
        }
        
        if (!/[A-Z]/.test(password)) {
            errors.push('Password should contain at least one uppercase letter');
        }
        
        if (!/[a-z]/.test(password)) {
            errors.push('Password should contain at least one lowercase letter');
        }
        
        if (!/\d/.test(password)) {
            errors.push('Password should contain at least one number');
        }
        
        return {
            valid: errors.length === 0,
            errors,
            score: this.calculatePasswordScore(password),
            strength: this.getStrengthLabel(password)
        };
    }
    
    static calculatePasswordScore(password) {
        let score = 0;
        if (password.length >= 8) score += 20;
        if (password.length >= 12) score += 20;
        if (/[A-Z]/.test(password)) score += 20;
        if (/[a-z]/.test(password)) score += 20;
        if (/\d/.test(password)) score += 10;
        if (/[^A-Za-z0-9]/.test(password)) score += 10;
        return Math.min(score, 100);
    }
    
    static getStrengthLabel(password) {
        const score = this.calculatePasswordScore(password);
        if (score >= 80) return 'Very Strong';
        if (score >= 60) return 'Strong';
        if (score >= 40) return 'Good';
        if (score >= 20) return 'Weak';
        return 'Very Weak';
    }
    
    static generateSecurePassword(length = 16) {
        const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
        let password = '';
        for (let i = 0; i < length; i++) {
            password += charset[crypto.randomInt(0, charset.length)];
        }
        return password;
    }
}

// ==================== XSTAG CORE ====================

class XStagCore {
    static async encryptAndHide({
        imageBuffer,
        message,
        password
    }) {
        try {
            const operationId = uuidv4();
            
            // Validate password
            const passwordValidation = SecurityManager.validatePassword(password);
            if (!passwordValidation.valid && password.length < 8) {
                throw new Error(`Password validation failed: ${passwordValidation.errors.join(', ')}`);
            }
            
            // Create metadata
            const metadata = {
                id: operationId,
                timestamp: new Date().toISOString(),
                version: '1.0.0',
                messageLength: message.length
            };
            
            // Encrypt message with metadata
            const messageWithMetadata = JSON.stringify({
                metadata,
                message,
                timestamp: Date.now()
            });
            
            const encryptedData = await EncryptionEngine.encrypt(
                messageWithMetadata,
                password
            );
            
            // Hide in image
            const stegoImage = await SteganographyEngine.hideData(
                imageBuffer,
                encryptedData
            );
            
            return {
                success: true,
                image: stegoImage,
                metadata,
                operationId
            };
            
        } catch (error) {
            throw new Error(`Encryption workflow failed: ${error.message}`);
        }
    }
    
    static async extractAndDecrypt({
        imageBuffer,
        password
    }) {
        try {
            // Extract data
            const extractedData = await SteganographyEngine.extractData(imageBuffer);
            
            // Decrypt
            const decrypted = await EncryptionEngine.decrypt(extractedData, password);
            const parsed = JSON.parse(decrypted);
            
            return {
                success: true,
                message: parsed.message,
                metadata: parsed.metadata,
                extractedAt: new Date().toISOString()
            };
            
        } catch (error) {
            throw new Error(`Extraction workflow failed: ${error.message}`);
        }
    }
    
    static async analyzeCapacity(imageBuffer) {
        try {
            const metadata = await sharp(imageBuffer).metadata();
            const capacity = SteganographyEngine.calculateCapacity(metadata);
            
            return {
                ...capacity,
                imageInfo: {
                    width: metadata.width,
                    height: metadata.height,
                    format: metadata.format,
                    channels: metadata.channels,
                    size: imageBuffer.length
                }
            };
        } catch (error) {
            throw new Error(`Capacity analysis failed: ${error.message}`);
        }
    }
    
    static getAvailableMethods() {
        return {
            steganography: 'LSB Standard',
            encryption: 'AES-256-GCM'
        };
    }
}

// ==================== EXPORT ====================

module.exports = {
    XStagCore,
    EncryptionEngine,
    SteganographyEngine,
    SecurityManager,
    CONFIG
};
