// popup.js
/* global chrome */
const fileInput = document.getElementById('fileInput');
const scanBtn   = document.getElementById('scanBtn');
const statusDiv = document.getElementById('status');

// --- Helper function to convert ArrayBuffer to Base64 ---
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    try {
        // btoa handles binary strings
        return btoa(binary);
    } catch (e) {
        console.error("Error in btoa:", e);
        // Fallback or error handling if btoa fails (e.g., invalid characters)
        // This shouldn't happen with typical file bytes, but good to be aware.
        return null; // Indicate failure
    }
}
// --- End Helper ---


scanBtn.addEventListener('click', async () => { // Make the event listener async
    const file = fileInput.files[0];
    if (!file) {
        statusDiv.textContent = 'Please select a .exe or .dll file first.';
        return;
    }

    const fileName = file.name.toLowerCase();
    if (!fileName.endsWith('.exe') && !fileName.endsWith('.dll')) {
        statusDiv.textContent = 'Invalid file type. Only .exe or .dll supported.';
        return;
    }

    statusDiv.textContent = 'Reading & preparing file...'; // Updated message
    scanBtn.disabled = true;
    fileInput.disabled = true;

    try {
        const arrayBuffer = await file.arrayBuffer();
        console.log(`Popup: Read ${file.name} into ArrayBuffer, size: ${arrayBuffer.byteLength}`);

        // Convert ArrayBuffer to Base64 string
        const base64String = arrayBufferToBase64(arrayBuffer);

        if (!base64String) {
             throw new Error("Failed to convert file content to Base64.");
        }
        console.log(`Popup: Converted ArrayBuffer to Base64 (first 50 chars): ${base64String.substring(0, 50)}...`);


        statusDiv.textContent = 'Sending file data to background...';

        // Send the Base64 string and metadata
        chrome.runtime.sendMessage({
            type: 'SCAN_FILE_BASE64', // *** NEW MESSAGE TYPE ***
            fileData: {
                base64: base64String, // Send the string
                name: file.name,
                type: file.type
            }
        }, (response) => {
            // ... (same response handling logic as before) ...
            if (chrome.runtime.lastError) {
                statusDiv.textContent = 'Error sending to background: ' + chrome.runtime.lastError.message;
                console.error("Popup: Chrome runtime error:", chrome.runtime.lastError.message);
            } else if (response) {
                 console.log("Popup: Response from background script (initial ack):", response);
                 if (response.status === 'SUBMISSION_INITIATED') {
                    statusDiv.textContent = response.message || 'File sent to backend. Waiting for results...';
                 } else if (response.status && (response.status.startsWith('ERROR_') || response.status.startsWith('FAIL'))) {
                    statusDiv.textContent = `Error: ${response.message || 'Failed to initiate scan via background.'}`;
                 } else {
                    statusDiv.textContent = 'Scan initiation response: ' + (response.message || JSON.stringify(response));
                 }
            } else {
                 statusDiv.textContent = 'No initial response from background script.';
                 console.error("Popup: No initial response from background script.");
            }
        });

    } catch (err) {
        statusDiv.textContent = 'Error reading/preparing file: ' + err.message;
        console.error("Popup: Error reading file or converting to Base64:", err);
        scanBtn.disabled = false;
        fileInput.disabled = false;
    }
});

// --- Listener for updates from background (remains the same) ---
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log("Popup: Received message from background:", request);
    if (request.type === "SCAN_UPDATE") {
        statusDiv.textContent = `Update for "${request.data.fileName}": ${request.data.message}`;
        scanBtn.disabled = true;
        fileInput.disabled = true;
    } else if (request.type === "SCAN_RESULT") {
        const resultData = request.data;
        let message = `Scan Complete for "${resultData.fileName}"!\nVerdict: ${resultData.verdict.toUpperCase()}\nConfidence: ${Math.round(resultData.confidence_malicious*100)}%\nStage: ${resultData.stage}`;
        if (resultData.jobId) message += `\n(Job ID: ${resultData.jobId})`;
        statusDiv.innerHTML = message.replace(/\n/g, '<br>');
        scanBtn.disabled = false;
        fileInput.disabled = false;
        fileInput.value = "";
    } else if (request.type === "SCAN_ERROR") {
        let errorMessage = `Error for "${request.data.fileName}": ${request.data.message}`;
        if (request.data.jobId) errorMessage += ` (Job ID: ${request.data.jobId})`;
        statusDiv.textContent = errorMessage;
        scanBtn.disabled = false;
        fileInput.disabled = false;
    }
});

// --- DOMContentLoaded listener (remains the same) ---
document.addEventListener('DOMContentLoaded', () => {
    statusDiv.textContent = 'Select a file to scan.';
    scanBtn.disabled = false;
    fileInput.disabled = false;
});