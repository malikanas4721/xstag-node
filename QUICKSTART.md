# Quick Start Guide

## Get Started in 3 Steps

### 1. Install Dependencies
```bash
npm install
```

### 2. Start the Server
```bash
npm start
```
Or for development with auto-reload:
```bash
npm run dev
```

### 3. Open in Browser
Navigate to: **http://localhost:3000**

## First Use

1. **Upload an image** (PNG recommended for best quality)
2. **Enter your secret message**
3. **Create a strong password** (use the password generator button)
4. **Select a steganography method** (Enhanced LSB is recommended)
5. **Click "Encrypt & Download"**

The encrypted image will be downloaded automatically.

## Decrypting

1. **Upload the encrypted image**
2. **Enter the password** you used during encryption
3. **Click "Decrypt Message"**

Your message will be displayed!

## Troubleshooting

- **Port in use?** Change `PORT` in `.env` file
- **Module errors?** Run `npm install` again
- **Can't decrypt?** Make sure you're using the correct password and the image was encrypted with XStag Pro

## Need Help?

Check the full README.md for detailed documentation.

