// XStag Pro - Main JavaScript
document.addEventListener('DOMContentLoaded', function () {
    console.log('XStag Pro UI Initialized');

    // ==================== GLOBAL STATE ====================
    let currentUser = null;
    let currentSection = 'encrypt';
    let firebaseApp = null;
    let firebaseAuth = null;

    // ==================== FIREBASE INITIALIZATION ====================
    // Prefer config from index.html (window.firebaseConfig), fall back to placeholders
    const firebaseConfig = (window.firebaseConfig && window.firebaseConfig.apiKey)
        ? window.firebaseConfig
        : {
            apiKey: "YOUR_API_KEY",
            authDomain: "YOUR_AUTH_DOMAIN",
            projectId: "YOUR_PROJECT_ID",
            storageBucket: "YOUR_STORAGE_BUCKET",
            messagingSenderId: "YOUR_MESSAGING_SENDER_ID",
            appId: "YOUR_APP_ID"
        };

    // Initialize Firebase (only if real config is provided)
    if (firebaseConfig.apiKey && firebaseConfig.apiKey !== "YOUR_API_KEY") {
        try {
            firebaseApp = firebase.initializeApp(firebaseConfig);
            firebaseAuth = firebase.auth();
            console.log('Firebase initialized');
        } catch (error) {
            console.error('Firebase initialization error:', error);
        }
    } else {
        console.warn('Firebase config not set. Please configure Firebase in script.js');
    }

    // ==================== DOM ELEMENTS ====================
    const elements = {
        // Encrypt elements
        encryptUpload: document.getElementById('encrypt-upload'),
        encryptFileInput: document.getElementById('encrypt-file'),
        encryptPreview: document.getElementById('encrypt-preview'),
        encryptPreviewImg: document.getElementById('encrypt-preview-img'),
        encryptFileName: document.getElementById('encrypt-file-name'),
        encryptFileInfo: document.getElementById('encrypt-file-info'),
        encryptMessage: document.getElementById('encrypt-message'),
        charCount: document.getElementById('char-count'),
        capacityInfo: document.getElementById('capacity-info'),
        encryptPassword: document.getElementById('encrypt-password'),
        passwordStrengthBar: document.getElementById('password-strength-bar'),
        passwordStrengthText: document.getElementById('password-strength-text'),
        passwordScore: document.getElementById('password-score'),
        generatePasswordBtn: document.getElementById('generate-password'),
        encryptBtn: document.getElementById('encrypt-btn'),
        encryptStatus: document.getElementById('encrypt-status'),
        encryptProgress: document.getElementById('encrypt-progress'),
        encryptProgressBar: document.getElementById('encrypt-progress-bar'),
        encryptProgressPercent: document.getElementById('encrypt-progress-percent'),
        removeEncryptImage: document.getElementById('remove-encrypt-image'),

        // Decrypt elements
        decryptUpload: document.getElementById('decrypt-upload'),
        decryptFileInput: document.getElementById('decrypt-file'),
        decryptPreview: document.getElementById('decrypt-preview'),
        decryptPreviewImg: document.getElementById('decrypt-preview-img'),
        decryptFileName: document.getElementById('decrypt-file-name'),
        decryptFileInfo: document.getElementById('decrypt-file-info'),
        decryptPassword: document.getElementById('decrypt-password'),
        decryptBtn: document.getElementById('decrypt-btn'),
        decryptStatus: document.getElementById('decrypt-status'),
        decryptProgress: document.getElementById('decrypt-progress'),
        decryptProgressBar: document.getElementById('decrypt-progress-bar'),
        decryptProgressPercent: document.getElementById('decrypt-progress-percent'),
        decryptResult: document.getElementById('decrypt-result'),
        decryptedMessage: document.getElementById('decrypted-message'),
        copyMessageBtn: document.getElementById('copy-message'),
        saveMessageBtn: document.getElementById('save-message'),
        removeDecryptImage: document.getElementById('remove-decrypt-image'),

        // Toast container
        toastContainer: document.getElementById('toast-container')
    };

    // ==================== UTILITY FUNCTIONS ====================

    // Clear all authentication input fields
    function clearAuthInputs() {
        // Clear login form
        const loginEmail = document.getElementById('login-email');
        const loginPassword = document.getElementById('login-password');
        if (loginEmail) loginEmail.value = '';
        if (loginPassword) loginPassword.value = '';

        // Clear signup form
        const signupName = document.getElementById('signup-name');
        const signupSurname = document.getElementById('signup-surname');
        const signupEmail = document.getElementById('signup-email');
        const signupPassword = document.getElementById('signup-password');
        if (signupName) signupName.value = '';
        if (signupSurname) signupSurname.value = '';
        if (signupEmail) signupEmail.value = '';
        if (signupPassword) signupPassword.value = '';

        // Clear status messages
        const loginStatus = document.getElementById('login-status');
        const signupStatus = document.getElementById('signup-status');
        if (loginStatus) loginStatus.textContent = '';
        if (signupStatus) signupStatus.textContent = '';
    }

    // Clear all encryption/decryption state
    function clearEncryptionState() {
        // Clear encrypt section
        if (elements.encryptFileInput) elements.encryptFileInput.value = '';
        if (elements.encryptPreview) elements.encryptPreview.style.display = 'none';
        if (elements.encryptMessage) elements.encryptMessage.value = '';
        if (elements.encryptPassword) elements.encryptPassword.value = '';
        if (elements.charCount) elements.charCount.textContent = '0';
        if (elements.capacityInfo) elements.capacityInfo.textContent = '';
        if (elements.encryptStatus) elements.encryptStatus.style.display = 'none';
        if (elements.passwordStrengthBar) elements.passwordStrengthBar.style.width = '0%';
        if (elements.passwordScore) elements.passwordScore.textContent = '0%';
        if (elements.passwordStrengthText) elements.passwordStrengthText.textContent = 'Password strength';
        resetProgress('encrypt');

        // Clear decrypt section
        if (elements.decryptFileInput) elements.decryptFileInput.value = '';
        if (elements.decryptPreview) elements.decryptPreview.style.display = 'none';
        if (elements.decryptPassword) elements.decryptPassword.value = '';
        if (elements.decryptStatus) elements.decryptStatus.style.display = 'none';
        if (elements.decryptResult) elements.decryptResult.style.display = 'none';
        if (elements.decryptedMessage) elements.decryptedMessage.textContent = 'No message extracted yet.';
        resetProgress('decrypt');
    }

    // Update button states based on authentication
    function updateButtonStates() {
        const isLoggedIn = currentUser !== null;

        // Update encrypt button
        if (elements.encryptBtn) {
            if (!isLoggedIn) {
                elements.encryptBtn.disabled = true;
                elements.encryptBtn.title = 'Please login to use encryption';
                elements.encryptBtn.style.opacity = '0.6';
                elements.encryptBtn.style.cursor = 'not-allowed';
            } else {
                elements.encryptBtn.disabled = false;
                elements.encryptBtn.title = '';
                elements.encryptBtn.style.opacity = '1';
                elements.encryptBtn.style.cursor = 'pointer';
            }
        }

        // Update decrypt button
        if (elements.decryptBtn) {
            if (!isLoggedIn) {
                elements.decryptBtn.disabled = true;
                elements.decryptBtn.title = 'Please login to use decryption';
                elements.decryptBtn.style.opacity = '0.6';
                elements.decryptBtn.style.cursor = 'not-allowed';
            } else {
                elements.decryptBtn.disabled = false;
                elements.decryptBtn.title = '';
                elements.decryptBtn.style.opacity = '1';
                elements.decryptBtn.style.cursor = 'pointer';
            }
        }
    }

    // Safe JSON parsing helper
    async function parseJSONResponse(response) {
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            const text = await response.text();
            throw new Error(`Server returned non-JSON response: ${text.substring(0, 200)}`);
        }
        return await response.json();
    }

    function showToast(message, type = 'info', duration = 5000) {
        if (!elements.toastContainer) return;

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;

        const iconMap = {
            success: 'check-circle',
            error: 'exclamation-circle',
            warning: 'exclamation-triangle',
            info: 'info-circle'
        };

        toast.innerHTML = `
            <i class="fas fa-${iconMap[type] || 'info-circle'} toast-icon"></i>
            <span>${message}</span>
        `;

        elements.toastContainer.appendChild(toast);

        // Animate in
        setTimeout(() => toast.classList.add('show'), 10);

        // Remove after duration
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, 300);
        }, duration);
    }

    function showStatus(element, message, type = 'info') {
        if (!element) return;

        element.textContent = message;
        element.className = `status-message ${type}`;
        element.style.display = 'flex';

        // Auto-hide success/info messages
        if (type !== 'error') {
            setTimeout(() => {
                if (element.textContent === message) {
                    element.style.display = 'none';
                }
            }, 10000); // Increased from 5000 to 10000 (10 seconds)
        }
    }

    function updateProgress(type, percent) {
        const progressBar = elements[`${type}ProgressBar`];
        const progressPercent = elements[`${type}ProgressPercent`];
        const progressContainer = elements[`${type}Progress`];

        if (progressBar) progressBar.style.width = `${percent}%`;
        if (progressPercent) progressPercent.textContent = `${percent}%`;
        if (progressContainer) progressContainer.style.display = 'block';
    }

    function resetProgress(type) {
        updateProgress(type, 0);
        const progressContainer = elements[`${type}Progress`];
        if (progressContainer) progressContainer.style.display = 'none';
    }

    function checkPasswordStrength(password) {
        if (!password) {
            if (elements.passwordStrengthBar) elements.passwordStrengthBar.style.width = '0%';
            if (elements.passwordScore) elements.passwordScore.textContent = '0%';
            if (elements.passwordStrengthText) elements.passwordStrengthText.textContent = 'Password strength';
            return;
        }

        let score = 0;
        if (password.length >= 8) score += 20;
        if (password.length >= 12) score += 20;
        if (/[A-Z]/.test(password)) score += 20;
        if (/[a-z]/.test(password)) score += 20;
        if (/\d/.test(password)) score += 10;
        if (/[^A-Za-z0-9]/.test(password)) score += 10;

        const strengthBar = elements.passwordStrengthBar;
        const strengthText = elements.passwordStrengthText;
        const scoreElement = elements.passwordScore;

        if (strengthBar) strengthBar.style.width = `${score}%`;
        if (scoreElement) scoreElement.textContent = `${score}%`;

        let text, statusClass;
        if (score < 40) {
            text = 'Weak';
            statusClass = 'weak';
        } else if (score < 70) {
            text = 'Fair';
            statusClass = 'fair';
        } else if (score < 90) {
            text = 'Good';
            statusClass = 'good';
        } else {
            text = 'Strong';
            statusClass = 'strong';
        }

        if (strengthBar) {
            strengthBar.classList.remove('weak', 'fair', 'good', 'strong');
            strengthBar.classList.add(statusClass);
        }
        if (strengthText) {
            strengthText.textContent = text;
            strengthText.style.color = ''; // Use CSS default or class-based color
        }
    }

    function generateSecurePassword() {
        const length = 16;
        const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
        let password = '';

        // Ensure at least one of each type
        password += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random() * 26)];
        password += 'abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random() * 26)];
        password += '0123456789'[Math.floor(Math.random() * 10)];
        password += '!@#$%^&*()_+-=[]{}|;:,.<>?'[Math.floor(Math.random() * 30)];

        // Fill remaining
        for (let i = password.length; i < length; i++) {
            password += charset[Math.floor(Math.random() * charset.length)];
        }

        // Shuffle
        password = password.split('').sort(() => Math.random() - 0.5).join('');

        return password;
    }

    function handleFileUpload(file, type) {
        // Check authentication first
        if (!currentUser) {
            showToast('Please login or signup to use encryption/decryption', 'warning');
            showSection('settings');
            return false;
        }

        if (!file || !file.type.startsWith('image/')) {
            showToast('Please upload an image file', 'error');
            return false;
        }

        if (file.size > 50 * 1024 * 1024) {
            showToast('File too large. Max 50MB', 'error');
            return false;
        }

        const previewImg = elements[`${type}PreviewImg`];
        const preview = elements[`${type}Preview`];
        const fileName = elements[`${type}FileName`];
        const fileInfo = elements[`${type}FileInfo`];
        const uploadArea = elements[`${type}Upload`];

        // Hide upload area and show preview
        if (uploadArea) uploadArea.style.display = 'none';
        if (preview) preview.style.display = 'block';
        if (previewImg) previewImg.style.display = 'block';

        const reader = new FileReader();
        reader.onload = (e) => {
            if (previewImg) previewImg.src = e.target.result;

            const img = new Image();
            img.onload = () => {
                if (fileName) fileName.textContent = file.name;
                if (fileInfo) {
                    fileInfo.textContent = `${img.width}×${img.height} • ${(file.size / 1024 / 1024).toFixed(2)}MB`;
                }

                // Analyze capacity for encrypt
                if (type === 'encrypt') {
                    analyzeImageCapacity(file, img);
                }
            };
            img.src = e.target.result;
        };
        reader.readAsDataURL(file);

        return true; // Indicate successful upload
    }

    async function analyzeImageCapacity(file, img) {
        try {
            const formData = new FormData();
            formData.append('image', file);

            const response = await fetch('/api/analyze/capacity', {
                method: 'POST',
                body: formData
            });

            if (response.ok) {
                const result = await parseJSONResponse(response);
                if (result.success && elements.capacityInfo) {
                    const capacity = result.analysis?.recommended || Math.floor((img.width * img.height * 3) / 8);
                    elements.capacityInfo.textContent = `Capacity: ~${capacity.toLocaleString()} chars`;
                }
            }
        } catch (error) {
            console.error('Capacity analysis failed:', error);
        }
    }

    function clearFile(type) {
        const fileInput = elements[`${type}FileInput`];
        const preview = elements[`${type}Preview`];
        const uploadArea = elements[`${type}Upload`];

        if (fileInput) fileInput.value = '';
        if (preview) preview.style.display = 'none';
        if (uploadArea) uploadArea.style.display = 'flex'; // Show upload area again

        if (type === 'encrypt' && elements.capacityInfo) {
            elements.capacityInfo.textContent = '';
        }
    }

    // ==================== EVENT LISTENERS ====================

    // Encrypt file upload
    if (elements.encryptUpload && elements.encryptFileInput) {
        elements.encryptUpload.addEventListener('click', () => {
            elements.encryptFileInput.click();
        });

        elements.encryptUpload.addEventListener('dragover', (e) => {
            e.preventDefault();
            elements.encryptUpload.classList.add('dragover');
        });

        elements.encryptUpload.addEventListener('dragleave', () => {
            elements.encryptUpload.classList.remove('dragover');
        });

        elements.encryptUpload.addEventListener('drop', (e) => {
            e.preventDefault();
            elements.encryptUpload.classList.remove('dragover');
            const file = e.dataTransfer.files[0];
            if (file) {
                elements.encryptFileInput.files = e.dataTransfer.files;
                const uploaded = handleFileUpload(file, 'encrypt');
                if (uploaded !== false) {
                    showStatus(elements.encryptStatus, 'Image loaded successfully', 'success');
                }
            }
        });

        elements.encryptFileInput.addEventListener('change', (e) => {
            if (e.target.files[0]) {
                const uploaded = handleFileUpload(e.target.files[0], 'encrypt');
                if (uploaded !== false) {
                    showStatus(elements.encryptStatus, 'Image loaded successfully', 'success');
                }
            }
        });
    }

    // Decrypt file upload
    if (elements.decryptUpload && elements.decryptFileInput) {
        elements.decryptUpload.addEventListener('click', () => {
            elements.decryptFileInput.click();
        });

        elements.decryptUpload.addEventListener('dragover', (e) => {
            e.preventDefault();
            elements.decryptUpload.classList.add('dragover');
        });

        elements.decryptUpload.addEventListener('dragleave', () => {
            elements.decryptUpload.classList.remove('dragover');
        });

        elements.decryptUpload.addEventListener('drop', (e) => {
            e.preventDefault();
            elements.decryptUpload.classList.remove('dragover');
            const file = e.dataTransfer.files[0];
            if (file) {
                elements.decryptFileInput.files = e.dataTransfer.files;
                const uploaded = handleFileUpload(file, 'decrypt');
                if (uploaded !== false) {
                    showStatus(elements.decryptStatus, 'Image loaded successfully', 'success');
                }
            }
        });

        elements.decryptFileInput.addEventListener('change', (e) => {
            if (e.target.files[0]) {
                const uploaded = handleFileUpload(e.target.files[0], 'decrypt');
                if (uploaded !== false) {
                    showStatus(elements.decryptStatus, 'Image loaded successfully', 'success');
                }
            }
        });
    }

    // Remove image buttons
    if (elements.removeEncryptImage) {
        elements.removeEncryptImage.addEventListener('click', (e) => {
            e.stopPropagation();
            clearFile('encrypt');
            if (elements.encryptStatus) elements.encryptStatus.style.display = 'none';
        });
    }

    if (elements.removeDecryptImage) {
        elements.removeDecryptImage.addEventListener('click', (e) => {
            e.stopPropagation();
            clearFile('decrypt');
            if (elements.decryptStatus) elements.decryptStatus.style.display = 'none';
        });
    }

    // Character counter
    if (elements.encryptMessage && elements.charCount) {
        elements.encryptMessage.addEventListener('input', function () {
            const count = this.value.length;
            if (elements.charCount) elements.charCount.textContent = count;
        });
    }

    // Password strength
    if (elements.encryptPassword) {
        elements.encryptPassword.addEventListener('input', function () {
            checkPasswordStrength(this.value);
        });
    }

    // Generate password button
    if (elements.generatePasswordBtn && elements.encryptPassword) {
        elements.generatePasswordBtn.addEventListener('click', () => {
            const password = generateSecurePassword();
            elements.encryptPassword.value = password;
            checkPasswordStrength(password);
            showToast('Secure password generated', 'success');
        });
    }

    // Encrypt button
    if (elements.encryptBtn) {
        elements.encryptBtn.addEventListener('click', async function () {
            // Check authentication first
            if (!currentUser) {
                showToast('Please login or signup to use encryption', 'warning');
                showSection('settings');
                return;
            }

            // Validate
            if (!elements.encryptFileInput || !elements.encryptFileInput.files[0]) {
                showStatus(elements.encryptStatus, 'Please select an image file', 'error');
                return;
            }

            if (!elements.encryptMessage || !elements.encryptMessage.value.trim()) {
                showStatus(elements.encryptStatus, 'Please enter a message to hide', 'error');
                return;
            }

            if (!elements.encryptPassword || !elements.encryptPassword.value.trim()) {
                showStatus(elements.encryptStatus, 'Please enter a password', 'error');
                return;
            }

            // Disable button
            const originalText = this.innerHTML;
            this.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Encrypting...';
            this.disabled = true;

            showStatus(elements.encryptStatus, 'Encrypting and hiding message in image...', 'info');
            updateProgress('encrypt', 20);

            try {
                const formData = new FormData();
                formData.append('image', elements.encryptFileInput.files[0]);
                formData.append('message', elements.encryptMessage.value);
                formData.append('password', elements.encryptPassword.value);

                updateProgress('encrypt', 40);

                const headers = {};
                if (currentUser && currentUser.token) {
                    headers['Authorization'] = `Bearer ${currentUser.token}`;
                }

                const response = await fetch('/api/encrypt', {
                    method: 'POST',
                    headers: headers,
                    body: formData
                });

                updateProgress('encrypt', 70);

                if (response.ok) {
                    const blob = await response.blob();
                    updateProgress('encrypt', 90);

                    // Download file
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `xstag-encrypted-${Date.now()}.png`;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    window.URL.revokeObjectURL(url);

                    updateProgress('encrypt', 100);
                    showStatus(elements.encryptStatus, '✅ Encryption successful! File downloaded.', 'success');
                    showToast('Encryption successful!', 'success');

                    setTimeout(() => {
                        resetProgress('encrypt');
                    }, 2000);
                } else {
                    const error = await parseJSONResponse(response);
                    throw new Error(error.error || 'Encryption failed');
                }
            } catch (error) {
                console.error('Encryption error:', error);
                showStatus(elements.encryptStatus, `❌ Error: ${error.message}`, 'error');
                showToast(error.message, 'error');
                resetProgress('encrypt');
            } finally {
                this.innerHTML = originalText;
                this.disabled = false;
            }
        });
    }

    // Decrypt button
    if (elements.decryptBtn) {
        elements.decryptBtn.addEventListener('click', async function () {
            // Check authentication first
            if (!currentUser) {
                showToast('Please login or signup to use decryption', 'warning');
                showSection('settings');
                return;
            }

            // Validate
            if (!elements.decryptFileInput || !elements.decryptFileInput.files[0]) {
                showStatus(elements.decryptStatus, 'Please select an encrypted image', 'error');
                return;
            }

            if (!elements.decryptPassword || !elements.decryptPassword.value.trim()) {
                showStatus(elements.decryptStatus, 'Please enter the password', 'error');
                return;
            }

            // Clear previous decrypted result
            if (elements.decryptResult) elements.decryptResult.style.display = 'none';
            if (elements.decryptedMessage) elements.decryptedMessage.textContent = 'No message extracted yet.';

            // Disable button
            const originalText = this.innerHTML;
            this.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Decrypting...';
            this.disabled = true;

            showStatus(elements.decryptStatus, 'Extracting and decrypting message...', 'info');
            updateProgress('decrypt', 20);

            try {
                const formData = new FormData();
                formData.append('image', elements.decryptFileInput.files[0]);
                formData.append('password', elements.decryptPassword.value);

                updateProgress('decrypt', 40);

                // Get fresh token if user is logged in
                let authHeader = {};
                if (currentUser && firebaseAuth) {
                    try {
                        const user = firebaseAuth.currentUser;
                        if (user) {
                            const token = await user.getIdToken();
                            authHeader['Authorization'] = `Bearer ${token}`;
                        }
                    } catch (error) {
                        console.error('Failed to get token:', error);
                    }
                } else if (currentUser && currentUser.token) {
                    authHeader['Authorization'] = `Bearer ${currentUser.token}`;
                }

                const response = await fetch('/api/decrypt', {
                    method: 'POST',
                    headers: authHeader,
                    body: formData
                });

                updateProgress('decrypt', 70);

                const result = await parseJSONResponse(response);
                updateProgress('decrypt', 90);

                if (response.ok && result.success) {
                    if (elements.decryptedMessage) {
                        elements.decryptedMessage.textContent = result.message;
                    }
                    if (elements.decryptResult) {
                        elements.decryptResult.style.display = 'block';
                    }

                    updateProgress('decrypt', 100);
                    showStatus(elements.decryptStatus, '✅ Decryption successful!', 'success');
                    showToast('Decryption successful!', 'success');

                    setTimeout(() => {
                        resetProgress('decrypt');
                    }, 2000);
                } else {
                    throw new Error(result.error || 'Decryption failed');
                }
            } catch (error) {
                console.error('Decryption error:', error);
                showStatus(elements.decryptStatus, `❌ Error: ${error.message}`, 'error');
                showToast(error.message, 'error');
                if (elements.decryptedMessage) {
                    elements.decryptedMessage.textContent = `Decryption failed: ${error.message}`;
                }
                if (elements.decryptResult) {
                    elements.decryptResult.style.display = 'block';
                }
                resetProgress('decrypt');
            } finally {
                this.innerHTML = originalText;
                this.disabled = false;
            }
        });
    }

    // Copy message button
    if (elements.copyMessageBtn && elements.decryptedMessage) {
        elements.copyMessageBtn.addEventListener('click', () => {
            const text = elements.decryptedMessage.textContent;
            if (text && text !== 'No message extracted yet.') {
                navigator.clipboard.writeText(text).then(() => {
                    showToast('Message copied to clipboard', 'success');
                }).catch(err => {
                    showToast('Failed to copy', 'error');
                });
            }
        });
    }

    // Save message button
    if (elements.saveMessageBtn && elements.decryptedMessage) {
        elements.saveMessageBtn.addEventListener('click', () => {
            const text = elements.decryptedMessage.textContent;
            if (text && text !== 'No message extracted yet.') {
                const blob = new Blob([text], { type: 'text/plain' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `xstag-message-${Date.now()}.txt`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
                showToast('Message saved as text file', 'success');
            }
        });
    }

    // ==================== NAVIGATION ====================
    function showSection(sectionName) {
        // Clear password fields when switching sections (prevent autofill)
        if (currentSection !== sectionName) {
            if (elements.encryptPassword) elements.encryptPassword.value = '';
            if (elements.decryptPassword) elements.decryptPassword.value = '';
            if (elements.passwordStrengthBar) elements.passwordStrengthBar.style.width = '0%';
            if (elements.passwordScore) elements.passwordScore.textContent = '0%';
            if (elements.passwordStrengthText) elements.passwordStrengthText.textContent = 'Password strength';
        }

        // Hide all sections
        document.querySelectorAll('.section-view').forEach(section => {
            section.style.display = 'none';
        });

        // Show selected section
        const targetSection = document.getElementById(`${sectionName}-section`);
        if (targetSection) {
            targetSection.style.display = 'block';
            currentSection = sectionName;
        }

        // Update active nav link
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('data-section') === sectionName) {
                link.classList.add('active');
            }
        });

        // Load dashboard if needed
        if (sectionName === 'dashboard') {
            loadDashboard();
        }
    }

    // Navigation link handlers
    document.querySelectorAll('.nav-link[data-section]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const section = link.getAttribute('data-section');
            showSection(section);
        });
    });

    // ==================== FIREBASE AUTHENTICATION ====================
    async function checkAuth() {
        if (!firebaseAuth) {
            currentUser = null;
            updateUserDisplay();
            return false;
        }

        return new Promise((resolve) => {
            firebaseAuth.onAuthStateChanged(async (user) => {
                if (user) {
                    // Get Firebase token
                    const token = await user.getIdToken();

                    // Verify token with backend
                    try {
                        const response = await fetch('/api/auth/verify', {
                            method: 'POST',
                            headers: {
                                'Authorization': `Bearer ${token}`
                            }
                        });

                        // Check if response is JSON
                        const contentType = response.headers.get('content-type');
                        if (!contentType || !contentType.includes('application/json')) {
                            throw new Error('Server returned non-JSON response');
                        }

                        const result = await parseJSONResponse(response);
                        if (result.success && result.user) {
                            currentUser = result.user;
                            currentUser.token = token; // Store token for API calls
                            updateUserDisplay();
                            resolve(true);
                        } else {
                            currentUser = null;
                            updateUserDisplay();
                            resolve(false);
                        }
                    } catch (error) {
                        console.error('Token verification failed:', error);
                        currentUser = null;
                        updateUserDisplay();
                        resolve(false);
                    }
                } else {
                    currentUser = null;
                    updateUserDisplay();
                    resolve(false);
                }
            });
        });
    }

    // Login function
    async function loginUser(email, password) {
        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email, password })
            });

            const result = await parseJSONResponse(response);
            if (result.success && result.token) {
                // Store token
                localStorage.setItem('auth_token', result.token);
                currentUser = result.user;
                currentUser.token = result.token;
                updateUserDisplay();
                showToast('Login successful!', 'success');
                return true;
            } else {
                showToast(result.error || 'Login failed', 'error');
                return false;
            }
        } catch (error) {
            showToast(error.message || 'Login failed', 'error');
            return false;
        }
    }

    // Signup function
    async function signupUser(name, email, password) {
        try {
            const surname = document.getElementById('signup-surname')?.value || '';
            const fullName = surname ? `${name} ${surname}` : name;

            const response = await fetch('/api/auth/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ name: fullName, email, password })
            });

            const result = await parseJSONResponse(response);
            if (result.success) {
                showToast('Account created successfully! Please login.', 'success');
                // Switch to login form
                document.querySelector('.auth-switch-link[data-switch="login"]')?.click();
                return true;
            } else {
                showToast(result.error || 'Signup failed', 'error');
                return false;
            }
        } catch (error) {
            showToast(error.message || 'Signup failed', 'error');
            return false;
        }
    }

    // Logout function
    async function logoutUser() {
        try {
            // Sign out from Firebase if available
            if (firebaseAuth) {
                await firebaseAuth.signOut();
            }

            // Clear localStorage
            localStorage.removeItem('auth_token');

            // Clear current user
            currentUser = null;

            // Clear all auth inputs
            clearAuthInputs();

            // Clear all encryption/decryption state
            clearEncryptionState();

            // Update UI
            updateUserDisplay();

            // Navigate to settings to show login form
            showSection('settings');

            showToast('Logged out successfully', 'success');
        } catch (error) {
            console.error('Logout error:', error);
            showToast('Logout failed', 'error');
        }
    }

    function updateUserDisplay() {
        const userProfile = document.getElementById('user-profile');
        const userName = document.getElementById('user-name');
        const userPicture = document.getElementById('user-picture');
        const loginSection = document.getElementById('login-section');
        const userInfoDisplay = document.getElementById('user-info-display');
        const settingsUserName = document.getElementById('settings-user-name');
        const settingsUserEmail = document.getElementById('settings-user-email');
        const settingsUserPicture = document.getElementById('settings-user-picture');
        const dashboardLoginMessage = document.getElementById('dashboard-login-message');

        if (currentUser) {
            // Show user profile in navbar
            if (userProfile) userProfile.style.display = 'flex';
            if (userName) userName.textContent = currentUser.name;
            if (userPicture) userPicture.src = currentUser.picture || '';

            // Update settings page
            if (loginSection) loginSection.style.display = 'none';
            if (userInfoDisplay) userInfoDisplay.style.display = 'block';
            if (settingsUserName) settingsUserName.textContent = currentUser.name;
            if (settingsUserEmail) settingsUserEmail.textContent = currentUser.email;
            if (settingsUserPicture) settingsUserPicture.src = currentUser.picture || '';

            // Hide dashboard login message
            if (dashboardLoginMessage) dashboardLoginMessage.style.display = 'none';
        } else {
            // Hide user profile in navbar
            if (userProfile) userProfile.style.display = 'none';
            if (userName) userName.textContent = '';
            if (userPicture) userPicture.src = '';

            // Show login section
            if (loginSection) loginSection.style.display = 'block';
            if (userInfoDisplay) userInfoDisplay.style.display = 'none';

            // Clear settings user info
            if (settingsUserName) settingsUserName.textContent = '';
            if (settingsUserEmail) settingsUserEmail.textContent = '';
            if (settingsUserPicture) settingsUserPicture.src = '';

            // Show dashboard login message
            if (dashboardLoginMessage) dashboardLoginMessage.style.display = 'block';
        }

        // Update button states
        updateButtonStates();
    }

    // Auth form switching
    document.querySelectorAll('.auth-switch-link').forEach(link => {
        link.addEventListener('click', () => {
            const switchTo = link.getAttribute('data-switch');

            // Clear all auth inputs when switching forms - prevents auto-fill, allows suggestions
            clearAuthInputs();

            // Hide all forms
            document.getElementById('login-form').classList.remove('active');
            document.getElementById('signup-form').classList.remove('active');
            document.getElementById('login-form').style.display = 'none';
            document.getElementById('signup-form').style.display = 'none';

            // Show selected form
            if (switchTo === 'login') {
                document.getElementById('login-form').classList.add('active');
                document.getElementById('login-form').style.display = 'block';
            } else if (switchTo === 'signup') {
                document.getElementById('signup-form').classList.add('active');
                document.getElementById('signup-form').style.display = 'block';
            }
        });
    });

    // Login button
    const loginBtn = document.getElementById('login-btn');
    if (loginBtn) {
        loginBtn.addEventListener('click', async () => {
            const email = document.getElementById('login-email').value;
            const password = document.getElementById('login-password').value;
            const statusEl = document.getElementById('login-status');

            if (!email || !password) {
                if (statusEl) {
                    statusEl.textContent = 'Please fill in all fields';
                    statusEl.className = 'auth-status error';
                }
                return;
            }

            loginBtn.disabled = true;
            loginBtn.textContent = 'Logging in...';

            const success = await loginUser(email, password);

            loginBtn.disabled = false;
            loginBtn.textContent = 'Login to your account';

            if (success) {
                if (statusEl) {
                    statusEl.textContent = 'Login successful!';
                    statusEl.className = 'auth-status success';
                }
                // Clear password after successful login
                const loginPassword = document.getElementById('login-password');
                if (loginPassword) loginPassword.value = '';

                showSection('dashboard');
            } else {
                if (statusEl) {
                    statusEl.textContent = 'Login failed. Please check your credentials.';
                    statusEl.className = 'auth-status error';
                }
            }
        });
    }

    // Signup button
    const signupBtn = document.getElementById('signup-btn');
    if (signupBtn) {
        signupBtn.addEventListener('click', async () => {
            const name = document.getElementById('signup-name').value;
            const email = document.getElementById('signup-email').value;
            const password = document.getElementById('signup-password').value;
            const statusEl = document.getElementById('signup-status');

            if (!name || !email || !password) {
                if (statusEl) {
                    statusEl.textContent = 'Please fill in all fields';
                    statusEl.className = 'auth-status error';
                }
                return;
            }

            if (password.length < 6) {
                if (statusEl) {
                    statusEl.textContent = 'Password must be at least 6 characters';
                    statusEl.className = 'auth-status error';
                }
                return;
            }

            signupBtn.disabled = true;
            signupBtn.textContent = 'Creating account...';

            const success = await signupUser(name, email, password);

            signupBtn.disabled = false;
            signupBtn.textContent = 'Register for free';

            if (success) {
                if (statusEl) {
                    statusEl.textContent = 'Account created successfully!';
                    statusEl.className = 'auth-status success';
                }
                showSection('dashboard');
            } else {
                if (statusEl) {
                    statusEl.textContent = 'Signup failed. Please try again.';
                    statusEl.className = 'auth-status error';
                }
            }
        });
    }

    // Logout button
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            logoutUser();
        });
    }

    // ==================== DASHBOARD ====================
    async function loadDashboard() {
        const encryptionCount = document.getElementById('encryption-count');
        const decryptionCount = document.getElementById('decryption-count');
        const totalOperations = document.getElementById('total-operations');
        const lastEncryptionTime = document.getElementById('last-encryption-time');
        const lastDecryptionTime = document.getElementById('last-decryption-time');

        if (!currentUser) {
            // Show login message
            return;
        }

        try {
            // Get fresh token
            let authHeader = {};
            if (firebaseAuth && firebaseAuth.currentUser) {
                try {
                    const token = await firebaseAuth.currentUser.getIdToken();
                    authHeader['Authorization'] = `Bearer ${token}`;
                } catch (error) {
                    console.error('Failed to get token:', error);
                }
            } else if (currentUser && currentUser.token) {
                authHeader['Authorization'] = `Bearer ${currentUser.token}`;
            }

            const response = await fetch('/api/dashboard/stats', {
                headers: authHeader
            });
            const result = await parseJSONResponse(response);

            if (result.success && result.stats) {
                const stats = result.stats;

                if (encryptionCount) encryptionCount.textContent = stats.encryptionCount || 0;
                if (decryptionCount) decryptionCount.textContent = stats.decryptionCount || 0;
                if (totalOperations) totalOperations.textContent = stats.totalOperations || 0;

                if (lastEncryptionTime) {
                    lastEncryptionTime.textContent = stats.lastEncryption
                        ? new Date(stats.lastEncryption).toLocaleString()
                        : 'Never';
                }

                if (lastDecryptionTime) {
                    lastDecryptionTime.textContent = stats.lastDecryption
                        ? new Date(stats.lastDecryption).toLocaleString()
                        : 'Never';
                }
            }
        } catch (error) {
            console.error('Failed to load dashboard:', error);
        }
    }

    // Initialize - Clear all fields on page load to prevent auto-fill
    // We clear fields periodically for the first 3 seconds to catch delayed browser auto-fill,
    // but stop immediately as soon as the user interacts with them.
    let autoFillClearInterval = setInterval(clearAuthInputs, 100);
    setTimeout(() => clearInterval(autoFillClearInterval), 3000);

    // Stop clearing if user types or focuses on any auth field
    ['login-email', 'login-password', 'signup-name', 'signup-surname', 'signup-email', 'signup-password'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.addEventListener('input', () => clearInterval(autoFillClearInterval));
            el.addEventListener('focus', () => clearInterval(autoFillClearInterval));
        }
    });

    // Hide user profile by default until auth check completes
    const userProfile = document.getElementById('user-profile');
    if (userProfile) userProfile.style.display = 'none';

    // Set initial button states (disabled until logged in)
    updateButtonStates();

    if (firebaseAuth) {
        checkAuth().then(() => {
            if (currentUser) {
                // User is logged in
                updateButtonStates();
            }
        });
    } else {
        // No Firebase, check for stored token
        const token = localStorage.getItem('auth_token');
        if (token) {
            // Try to verify token with backend
            fetch('/api/auth/verify', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            })
                .then(response => response.json())
                .then(result => {
                    if (result.success && result.user) {
                        currentUser = result.user;
                        currentUser.token = token;
                        updateUserDisplay();
                    }
                })
                .catch(error => {
                    console.error('Token verification failed:', error);
                    localStorage.removeItem('auth_token');
                });
        }
    }
    checkServerStatus();

    // Make showSection available globally
    window.showSection = showSection;
});

// Server status check
async function checkServerStatus() {
    try {
        const response = await fetch('/api/health');
        if (response.ok) {
            console.log('Server is online');
        }
    } catch (error) {
        console.error('Server is offline:', error);
    }
}
