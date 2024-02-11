function logRansomware(type, details) {
    const log = {
        type: type,
        timestamp: new Date().toISOString(),
        details: details
    };
    chrome.storage.local.get('ransomwareLogs', (data) => {
        const logs = data.ransomwareLogs || [];
        log.push(log);
        chrome.storage.local.set({ ransomwareLogs: logs });
    });
}
// Function to send a POST request to the Flask server
async function sendRequest(url, data) {
    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    });
    return await response.json();
}

// Event listener for URL checking
chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
    if (message.action === 'URLCheck') {
        try {
            const result = await sendRequest('flask_hack.py', { url: message.url });
            if (result && result.url_prediction && result.ransomware_prediction) {
                // Handle the predictions, maybe log them or take some action
                console.log('URL Prediction:', result.url_prediction);
                console.log('Ransomware Prediction:', result.ransomware_prediction);
            }
        } catch (error) {
            console.error('Error checking URL:', error);
        }
    }
});

chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
    if (message.action === 'PasswordStrengthCheck') {
        try {
            const result = await sendRequest('flask_hack.py', { password_length: message.password.length });
            if (result && result.password) {
                // Handle the generated password, maybe log it or send it back to the content script
                console.log('Generated Password:', result.password);
            }
        } catch (error) {
            console.error('Error generating password:', error);
        }
    }
});

// Event listener for ransomware detection
chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
    if (message.action === 'RansomwareDetection') {
        try {
            const result = await sendRequest('flask_hack.py', { file_data: message.file });
            if (result && result.prediction) {
                // Handle the ransomware prediction, maybe log it or send it back to the content script
                console.log('Ransomware Prediction:', result.prediction);
                chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
                    chrome.tabs.sendMessage(tabs[0].id, { action: 'ShowPopup', message: 'Ransomware detected!' });
                });
            }
        } catch (error) {
            console.error('Error detecting ransomware:', error);
        }
    }
});
// Event listener for email phishing detection
chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
    if (message.action === 'EmailPhishingDetection') {
        try {
            const result = await sendRequest('flask_hack.py', { email: message.email });
            if (result && result.email_prediction) {
                // Handle the email prediction, maybe log it or send it back to the content script
                console.log('Email Prediction:', result.email_prediction);
            }
        } catch (error) {
            console.error('Error checking email:', error);
        }
    }
});
// Event listener to show alert popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'ShowPopup') {
        alert(message.message);
    }
});
// Event listener for API:GetSystemDirectoryA
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'GetSystemDirectoryA') {
        logRansomware('api_call', { method: 'GetSystemDirectoryA', details: message.details });
    }
});

chrome.webRequest.onBeforeRequest.addListener((details) => {
    if (details.method === 'POST' && details.url.includes('CreateProcess')) {
        logRansomware('endpoint_activity', { type: 'process_creation', details: details });
    }
}, { urls: ['<all_urls>'] }, ['requestBody']);

// Implement listeners for other recommended APIs and endpoints according to the dataset
// For example:

// Event listener for API:WriteConsoleA
chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
    if (message.action === 'WriteConsoleA') {
        logRansomware('api_call', { method: 'WriteConsoleA', details: message.details });
    }
});

// Implement listeners for other recommended APIs and endpoints according to the dataset
// For example:

// Event listener for endpoint: File Write (CreateFile)
chrome.webRequest.onBeforeRequest.addListener((details) => {
    if (details.method === 'POST' && details.url.includes('CreateFile')) {
        logRansomware('endpoint_activity', { type: 'file_write', details: details });
    }
}, { urls: ['<all_urls>'] }, ['requestBody']);

// Implement listeners for other recommended endpoints according to the dataset
// For example:

// Event listener for endpoint: Registry Write (RegCreateKeyEx)
chrome.webRequest.onBeforeRequest.addListener((details) => {
    if (details.method === 'POST' && details.url.includes('RegCreateKeyEx')) {
        logRansomware('endpoint_activity', { type: 'registry_write', details: details });
    }
}, { urls: ['<all_urls>'] }, ['requestBody']);

// Implement listeners for other recommended endpoints according to the dataset
// For example:

// Event listener for endpoint: Network Connections (ConnectNamedPipe)
chrome.webRequest.onBeforeRequest.addListener((details) => {
    if (details.method === 'POST' && details.url.includes('ConnectNamedPipe')) {
        logRansomware('endpoint_activity', { type: 'network_connection', details: details });
    }
}, { urls: ['<all_urls>'] }, ['requestBody']);

// Implement listeners for other recommended endpoints according to the dataset
// For example:

// Event listener for endpoint: Cryptographic Operations (CryptAcquireContext)
chrome.webRequest.onBeforeRequest.addListener((details) => {
    if (details.method === 'POST' && details.url.includes('CryptAcquireContext')) {
        logRansomware('endpoint_activity', { type: 'crypto_operation', details: details });
    }
}, { urls: ['<all_urls>'] }, ['requestBody']);

// Implement listeners for other recommended endpoints according to the dataset
// For example:

// Event listener for endpoint: System Shutdown (ExitWindowsEx)
chrome.webRequest.onBeforeRequest.addListener((details) => {
    if (details.method === 'POST' && details.url.includes('ExitWindowsEx')) {
        logRansomware('endpoint_activity', { type: 'system_shutdown', details: details });
    }
}, { urls: ['<all_urls>'] }, ['requestBody']);
// Event listener for API:NtReadVirtualMemory
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'NtReadVirtualMemory') {
        logRansomware('api_call', { method: 'NtReadVirtualMemory', details: message.details });
    }
});
// Event listener for endpoint: File Read (CreateFileMapping)
chrome.webRequest.onBeforeRequest.addListener((details) => {
    if (details.method === 'POST' && details.url.includes('CreateFileMapping')) {
        logRansomware('endpoint_activity', { type: 'file_read', details: details });
    }
}, { urls: ['<all_urls>'] }, ['requestBody']);
// Event listener for endpoint: Registry Read (RegOpenKeyEx)
chrome.webRequest.onBeforeRequest.addListener((details) => {
    if (details.method === 'POST' && details.url.includes('RegOpenKeyEx')) {
        logRansomware('endpoint_activity', { type: 'registry_read', details: details });
    }
}, { urls: ['<all_urls>'] }, ['requestBody']);
// Event listener for endpoint: Network Connections (ConnectNamedPipe)
chrome.webRequest.onBeforeRequest.addListener((details) => {
    if (details.method === 'POST' && details.url.includes('ConnectNamedPipe')) {
        logRansomware('endpoint_activity', { type: 'network_connection', details: details });
    }
}, { urls: ['<all_urls>'] }, ['requestBody']);
// Event listener for endpoint: Cryptographic Operations (CryptGenKey)
chrome.webRequest.onBeforeRequest.addListener((details) => {
    if (details.method === 'POST' && details.url.includes('CryptGenKey')) {
        logRansomware('endpoint_activity', { type: 'crypto_operation', details: details });
    }
}, { urls: ['<all_urls>'] }, ['requestBody']);
// Event listener for endpoint: System Shutdown (InitiateShutdown)
chrome.webRequest.onBeforeRequest.addListener((details) => {
    if (details.method === 'POST' && details.url.includes('InitiateShutdown')) {
        logRansomware('endpoint_activity', { type: 'system_shutdown', details: details });
    }
}, { urls: ['<all_urls>'] }, ['requestBody']);
chrome.webRequest.onBeforeRequest.addListener((details) => {
    // TODO: Add code to log ransomware activities
}, { urls: ['<all_urls>'] }, ['requestBody']);

chrome.webRequest.onBeforeSendHeaders.addListener((details) => {
    // TODO: Add code to monitor for specific API call headers
}, { urls: ['<all_urls>'] }, ['requestHeaders']);

chrome.filesystem.requestFileSystemAccess((result) => {
    // TODO: Add code to monitor for specific file access events
});




