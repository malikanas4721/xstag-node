# XStag Professional - Image Steganography Suite

Professional-grade image steganography application with advanced encryption capabilities.

## Features

- 🔒 **Multiple Encryption Algorithms**: AES-256-GCM, AES-256-CBC, ChaCha20-Poly1305
- 🎨 **Advanced Steganography Methods**: LSB Standard, Enhanced, Random, Multi-bit, DCT, Color Palette
- 🛡️ **Security Levels**: Low, Medium, High, Military-grade
- 📊 **Capacity Analysis**: Analyze image capacity before encryption
- 🔐 **Password Strength Validation**: Built-in password strength checker
- 🚀 **High Performance**: Optimized for speed and efficiency
- 📱 **Modern UI**: Professional web interface

## Prerequisites

- Node.js >= 18.0.0
- npm >= 9.0.0

## Installation

1. **Clone or download the project**
   ```bash
   cd xstag-node
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables** (optional)
   ```bash
   cp .env.example .env
   ```
   Edit `.env` if you need to change the port or CORS settings.

4. **Create necessary directories** (automatically created on first run)
   - `uploads/` - For temporary file uploads
   - `logs/` - For application logs
   - `public/` - For static files

## Running the Application

### Development Mode
```bash
npm run dev
```
This uses `nodemon` to automatically restart the server on file changes.

### Production Mode
```bash
npm start
```

The server will start on `http://localhost:3000` (or the port specified in `.env`).

## Usage

1. **Open your browser** and navigate to `http://localhost:3000`
2. **Encrypt a message**:
   - Upload an image (PNG, JPEG, BMP, WebP, TIFF)
   - Enter your secret message
   - Set a strong password
   - Choose a steganography method
   - Click "Encrypt & Download"

3. **Decrypt a message**:
   - Upload an encrypted image
   - Enter the password used for encryption
   - Click "Decrypt Message"

## API Endpoints

### Health Check
```
GET /api/health
```

### System Status
```
GET /api/system/status
```

### Analyze Capacity
```
POST /api/analyze/capacity
Content-Type: multipart/form-data
Body: { image: File, method?: string }
```

### Encrypt & Hide
```
POST /api/encrypt
Content-Type: multipart/form-data
Body: {
  image: File,
  message: string,
  password: string,
  encryption?: string,
  method?: string,
  securityLevel?: string,
  options?: object
}
```

### Decrypt & Extract
```
POST /api/decrypt
Content-Type: multipart/form-data
Body: {
  image: File,
  password: string,
  method?: string
}
```

### Get Available Methods
```
GET /api/methods
```

### Password Analysis
```
POST /api/password/analyze
Content-Type: application/json
Body: { password: string }
```

## Configuration

### Supported Image Formats
- PNG (recommended)
- JPEG
- BMP
- WebP
- TIFF

### Maximum File Size
- Default: 50MB (configurable in `controllers/stegController.js`)

### Security Levels
- **LOW**: 50,000 PBKDF2 iterations
- **MEDIUM**: 100,000 iterations
- **HIGH**: 200,000 iterations
- **MILITARY**: 500,000 iterations

## Project Structure

```
xstag-node/
├── server.js                 # Main Express server
├── controllers/
│   └── stegController.js    # Steganography and encryption logic
├── public/
│   ├── index.html            # Web interface
│   ├── script.js             # Frontend JavaScript
│   └── style.css             # Styles (if separate)
├── uploads/                  # Temporary upload directory
├── logs/                     # Application logs
├── package.json              # Dependencies and scripts
└── README.md                 # This file
```

## Security Features

- ✅ Helmet.js for security headers
- ✅ CORS protection
- ✅ Rate limiting
- ✅ Input validation
- ✅ File type validation
- ✅ Automatic cleanup of temporary files
- ✅ Secure password hashing (PBKDF2)
- ✅ Strong encryption algorithms

## Troubleshooting

### Port Already in Use
If port 3000 is already in use, change the `PORT` in `.env` file.

### Module Not Found Errors
Run `npm install` to ensure all dependencies are installed.

### Image Processing Errors
- Ensure images are in supported formats
- Check file size (max 50MB)
- Verify image is not corrupted

### Extraction Fails
- Verify you're using the correct password
- Ensure the image was encrypted with XStag Pro
- Check that the steganography method matches

## Development

### Scripts
- `npm start` - Start the server
- `npm run dev` - Start with nodemon (auto-reload)
- `npm test` - Run tests (if configured)
- `npm run lint` - Run ESLint
- `npm run clean` - Clean temporary files

## License

MIT License

## Support

For issues and questions, please check the project documentation or create an issue in the repository.
