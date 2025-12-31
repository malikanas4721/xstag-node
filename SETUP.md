# Setup Instructions

## PowerShell Execution Policy Issue

If you're getting an error about execution policy, you have several options:

### Option 1: Use the Batch File (Easiest)
Simply double-click `start.bat` or run:
```cmd
start.bat
```

### Option 2: Use the PowerShell Script
Run:
```powershell
powershell -ExecutionPolicy Bypass -File start.ps1
```

### Option 3: Fix PowerShell Policy (Permanent)
Run PowerShell as Administrator and execute:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then you can use npm commands normally.

### Option 4: Use Command Prompt Instead
Open `cmd.exe` instead of PowerShell - npm will work there without any policy issues.

## Quick Start

1. **Install dependencies** (if not already installed):
   ```bash
   npm install
   ```

2. **Start the server**:
   ```bash
   npm start
   ```
   Or use `start.bat` or `start.ps1`

3. **Open browser**: http://localhost:3000

## Troubleshooting

- **Port 3000 in use?** Edit `.env` file and change `PORT=3000` to another port
- **Module errors?** Delete `node_modules` folder and run `npm install` again
- **Still having issues?** Use `start.bat` - it works in any Windows environment

