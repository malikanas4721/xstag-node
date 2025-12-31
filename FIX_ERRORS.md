# Fixing the "Cannot find module" Error

## The Problem
You're getting: `Error: Cannot find module 'dotenv'`

This means the npm packages haven't been installed yet.

## Solution: Install Dependencies

### Option 1: Using Command Prompt (cmd.exe) - Easiest
1. Open **Command Prompt** (not PowerShell)
2. Navigate to the project folder:
   ```cmd
   cd C:\Users\user\Downloads\xstag-node
   ```
3. Run:
   ```cmd
   npm install
   ```
4. Wait for it to finish (may take 1-2 minutes)
5. Then run:
   ```cmd
   npm start
   ```

### Option 2: Using PowerShell with Bypass
```powershell
powershell -ExecutionPolicy Bypass -Command "npm install"
```
Then:
```powershell
powershell -ExecutionPolicy Bypass -Command "npm start"
```

### Option 3: Update start.bat to Auto-Install
The `start.bat` file should already check and install, but if it doesn't work, run:
```cmd
npm install
```
manually first.

## What npm install Does
- Downloads all required packages listed in `package.json`
- Creates/updates the `node_modules` folder
- Installs dependencies like: express, multer, sharp, dotenv, etc.

## After Installation
Once `npm install` completes successfully, you should see:
- A `node_modules` folder with many subfolders
- No errors when running `npm start`

## Quick Fix Command
Open **Command Prompt** and run:
```cmd
cd C:\Users\user\Downloads\xstag-node && npm install && npm start
```

This will:
1. Go to the project folder
2. Install all dependencies
3. Start the server

