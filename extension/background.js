// background.js
/* global chrome */

const BACKEND_URL = 'http://localhost:8000'; // Your backend URL

// --- Helper function to convert Base64 string to Blob ---
function base64ToBlob(base64, contentType = '', sliceSize = 512) {
    try {
        // atob decodes base64 -> binary string
        const byteCharacters = atob(base64);
        const byteArrays = [];

        for (let offset = 0; offset < byteCharacters.length; offset += sliceSize) {
            const slice = byteCharacters.slice(offset, offset + sliceSize);

            const byteNumbers = new Array(slice.length);
            for (let i = 0; i < slice.length; i++) {
                byteNumbers[i] = slice.charCodeAt(i);
            }

            const byteArray = new Uint8Array(byteNumbers);
            byteArrays.push(byteArray);
        }

        const blob = new Blob(byteArrays, {type: contentType});
        return blob;
    } catch (e) {
        console.error("Error converting Base64 to Blob:", e);
        return null; // Indicate failure
    }
}
// --- End Helper ---


// --- Listener for Base64 data ---
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === "SCAN_FILE_BASE64") { // *** LISTEN FOR NEW TYPE ***
        if (request.fileData &&
            typeof request.fileData.base64 === 'string' && // Check for base64 string
            typeof request.fileData.name === 'string' &&
            typeof request.fileData.type === 'string')
        {
            console.log(`Background: Received SCAN_FILE_BASE64 for ${request.fileData.name}`);
            try {
                // Convert Base64 string back to a Blob
                const fileBlob = base64ToBlob(request.fileData.base64, request.fileData.type);

                if (!fileBlob) {
                    throw new Error("Failed to convert received Base64 data back to Blob.");
                }

                console.log(`Background: Reconstructed Blob from Base64 for ${request.fileData.name}. Type: ${fileBlob.type}, Size: ${fileBlob.size}`);

                // Pass the new Blob and the original filename to the backend function
                sendFileToBackend(fileBlob, request.fileData.name, sendResponse);

            } catch (error) {
                console.error(`Background: Error processing Base64 data for ${request.fileData.name}:`, error);
                sendResponse({ status: "ERROR_BASE64_DECODE", message: "Failed to process received file data."});
                createNotification('Scan Error', `Internal error processing Base64 file data for "${request.fileData.name}".`);
            }
        } else {
            console.error("Background: SCAN_FILE_BASE64 received invalid or incomplete data structure.", request.fileData);
            sendResponse({ status: "ERROR_INVALID_DATA", message: "Invalid Base64 file data structure received."});
        }
        // Return true because sendFileToBackend will call sendResponse asynchronously
        return true;
    }
    // Add other message listeners here if needed
});


/**
 * Sends the file Blob to the backend for scanning.
 * (This function remains largely the same as the previous ArrayBuffer version,
 *  as it now receives a correctly reconstructed Blob)
 * @param {Blob} fileBlob The file content as a Blob object.
 * @param {string} originalFileName The original name of the file.
 * @param {Function} initialSendResponse Function to call to acknowledge message receipt.
 */
async function sendFileToBackend(fileBlob, originalFileName, initialSendResponse) {
    const formData = new FormData();

    try {
        formData.append('file', fileBlob, originalFileName);
        console.log(`Background: Appended ${originalFileName} (from Base64->Blob) to FormData.`);
    } catch (e) {
        console.error(`Background: Critical error appending reconstructed Blob to FormData for ${originalFileName}:`, e);
        if (initialSendResponse) {
            initialSendResponse({ status: "ERROR_FORM_DATA", message: "Failed to prepare file data for upload." });
        }
        createNotification('Scan Error', `Internal error preparing "${originalFileName}" for upload.`);
        chrome.runtime.sendMessage({ type: "SCAN_ERROR", data: { fileName: originalFileName, message: `Internal error preparing file data.` } }).catch(e => console.warn("Could not send error message to popup:", e));
        return;
    }

    console.log(`Background: Sending ${originalFileName} to backend API: ${BACKEND_URL}/scan`);

    if (initialSendResponse) {
        initialSendResponse({ status: "SUBMISSION_INITIATED", message: "File data processed, sending to backend..." });
    }

    try {
        const response = await fetch(`${BACKEND_URL}/scan`, {
            method: 'POST',
            body: formData,
        });

        const result = await response.json();
        console.log(`Background: Initial scan response from backend for ${originalFileName}:`, response.status, result);

        // --- Handle backend responses (queued, completed_static, error) ---
        // (This logic remains the same as before)
        if (response.status === 202 && result.status === 'queued_for_dynamic' && result.job_id) {
             const queueMessage = `"${originalFileName}" queued for dynamic analysis (Job ID: ${result.job_id})`;
             createNotification('Scan In Progress', queueMessage);
             chrome.runtime.sendMessage({ type: "SCAN_UPDATE", data: { status: "QUEUED", jobId: result.job_id, fileName: originalFileName, message: queueMessage } }).catch(e => console.warn("Could not send queue update to popup:", e));
             pollForResult(result.job_id, originalFileName);

        } else if (response.ok && result.status === 'completed_static') {
             const staticResultMessage = `File: "${originalFileName}"\nVerdict: ${result.verdict.toUpperCase()}\nConfidence: ${Math.round(result.confidence_malicious*100)}%\nStage: ${result.stage}`;
             createNotification(`Scan Result: ${result.verdict.toUpperCase()}`, staticResultMessage);
             chrome.runtime.sendMessage({ type: "SCAN_RESULT", data: { fileName: originalFileName, ...result } }).catch(e => console.warn("Could not send static result to popup:", e));

        } else {
             const errorMessage = result.detail || result.message || `Scan failed with backend status ${response.status}`;
             console.error(`Background: Backend scan error for ${originalFileName}: ${errorMessage}`);
             createNotification('Scan Error', `Failed to scan "${originalFileName}": ${errorMessage}`);
             chrome.runtime.sendMessage({ type: "SCAN_ERROR", data: { fileName: originalFileName, message: errorMessage } }).catch(e => console.warn("Could not send backend error to popup:", e));
        }

    } catch (error) {
        // --- Handle network errors ---
        // (This logic remains the same as before)
        console.error(`Background: Network or fetch error scanning ${originalFileName}:`, error);
        const networkErrorMsg = `Network or backend connection error while scanning "${originalFileName}": ${error.message}`;
        createNotification('Scan Network Error', networkErrorMsg);
        chrome.runtime.sendMessage({ type: "SCAN_ERROR", data: { fileName: originalFileName, message: networkErrorMsg } }).catch(e => console.warn("Could not send network error to popup:", e));
    }
}


// --- Polling function (pollForResult) remains the same ---
async function pollForResult(jobId, originalFileName) {
    // ... (no changes needed in the polling logic itself) ...
    let attempts = 0;
    const maxAttempts = 20; // Poll for up to 5 minutes (20 * 15s)
    const interval = 15000; // 15 seconds
    const resultUrl = `${BACKEND_URL}/result/${jobId}`;
    console.log(`Background: Starting to poll ${resultUrl} for Job ID: ${jobId}`);

    const poller = setInterval(async () => {
        attempts++;
        if (attempts > maxAttempts) {
            clearInterval(poller);
            const timeoutMessage = `Dynamic analysis polling for "${originalFileName}" (Job ID: ${jobId}) timed out.`;
            console.warn(`Background: ${timeoutMessage}`);
            createNotification('Scan Timeout', timeoutMessage);
            chrome.runtime.sendMessage({ type: "SCAN_ERROR", data: { jobId: jobId, fileName: originalFileName, message: "Dynamic analysis polling timed out." } }).catch(e => console.warn("Could not send timeout error to popup:", e));
            return;
        }

        try {
            console.log(`Background: Polling for job ${jobId}, attempt ${attempts}`);
            const response = await fetch(resultUrl);

            if (!response.ok) {
                 if (response.status === 404) {
                    console.warn(`Background: Job ID ${jobId} not found during polling (404). May be pending or backend issue.`);
                    return; // Continue polling
                 } else {
                    throw new Error(`Backend polling returned status ${response.status}`);
                 }
            }

            const result = await response.json();
            console.log(`Background: Poll response for ${jobId}:`, result);

            if (result.status === 'completed_dynamic') {
                clearInterval(poller);
                const dynamicResultMessage = `File: "${originalFileName}" (Dynamic)\nVerdict: ${result.verdict.toUpperCase()}\nConfidence: ${Math.round(result.confidence*100)}%\nStage: ${result.stage}`;
                createNotification(`Scan Result: ${result.verdict.toUpperCase()}`, dynamicResultMessage);
                chrome.runtime.sendMessage({ type: "SCAN_RESULT", data: { jobId: jobId, fileName: originalFileName, ...result } }).catch(e => console.warn("Could not send dynamic result to popup:", e));

            } else if (result.status === 'error_dynamic') {
                clearInterval(poller);
                const dynamicErrorMessage = `Error during dynamic scan for "${originalFileName}" (Job ID: ${jobId}): ${result.error_message}`;
                console.error(`Background: ${dynamicErrorMessage}`);
                createNotification('Dynamic Scan Error', dynamicErrorMessage);
                chrome.runtime.sendMessage({ type: "SCAN_ERROR", data: { jobId: jobId, fileName: originalFileName, message: result.error_message } }).catch(e => console.warn("Could not send dynamic error to popup:", e));

            } else if (result.status === 'processing_dynamic' || result.status === 'pending') {
                 console.log(`Background: Job ${jobId} still processing dynamically or pending.`);
                 const updateMessage = result.message || "Dynamic analysis in progress...";
                 chrome.runtime.sendMessage({ type: "SCAN_UPDATE", data: { jobId: jobId, fileName: originalFileName, status: "PROCESSING", message: updateMessage} }).catch(e => console.warn("Could not send processing update to popup:", e));
            } else {
                 console.warn(`Background: Unknown status "${result.status}" received for job ${jobId}. Continuing poll.`);
            }
        } catch (error) {
            console.error(`Background: Error polling for job ${jobId}:`, error);
        }
    }, interval);
}


// --- Notification function (createNotification) remains the same ---
function createNotification(title, message, notificationId) {
    // ... (no changes needed) ...
    const id = notificationId || `scan_notif_${Date.now()}`;
    try {
        chrome.notifications.create(id, {
            type: 'basic',
            iconUrl: 'icons/icon128.png',
            title: title,
            message: message,
            priority: 1
        });
    } catch (e) {
        console.error("Error creating notification:", e);
    }
}

// --- Startup/Install listeners remain the same ---
chrome.runtime.onStartup.addListener(() => { /* ... */ });
chrome.runtime.onInstalled.addListener((details) => { /* ... */ });

console.log("Background service worker loaded (Base64 version) and listeners attached.");