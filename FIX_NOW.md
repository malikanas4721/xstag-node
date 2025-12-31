# 🔧 Fix Errors - Quick Guide

## The Error You're Seeing

```
Error: Cannot find module 'dotenv'
```

This means **dependencies are not installed**.

## ✅ Quick Fix (Choose One)

### Option 1: Use install.bat (Easiest)
1. **Double-click** `install.bat`
2. Wait for installation to complete
3. Then run `start.bat`

### Option 2: Use Command Prompt
1. Press `Win + R`
2. Type `cmd` and press Enter
3. Navigate to project:
   ```cmd
   cd C:\Users\user\Downloads\xstag-node
   ```
4. Run:
   ```cmd
   npm install
   ```
5. Wait for it to finish
6. Then run:
   ```cmd
   npm start
   ```

### Option 3: Fix PowerShell Policy (Permanent)
Run PowerShell **as Administrator**:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then you can use `npm install` normally.

## 📋 Step-by-Step

1. **Install dependencies:**
   - Run `install.bat` OR
   - Open Command Prompt and run `npm install`

2. **Start the server:**
   - Run `start.bat` OR
   - Run `npm start`

3. **Open browser:**
   - Go to: http://localhost:3000

## ⚠️ Common Issues

### "npm is not recognized"
- Make sure Node.js is installed
- Download from: https://nodejs.org/

### "Port 3000 already in use"
- Change port in `.env` file
- Or close the program using port 3000

### "Still getting module errors after install"
- Delete `node_modules` folder
- Delete `package-lock.json`
- Run `npm install` again

## ✅ After Installation

You should see:
- `node_modules` folder created
- No more "Cannot find module" errors
- Server starts successfully

---

**Need help?** Check `README.md` for full documentation.

