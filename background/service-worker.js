/**
 * WebShield Service Worker - Manifest V3 Background Script
 */

// Handle extension installation
chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'install') {
    console.log('WebShield Vulnerability Scanner installed successfully.');
    await chrome.storage.local.set({
      scanHistory: [],
      settings: { autoScan: false, badgeAlerts: true }
    });
  }
});

// Listener for messages from Popup or Content Scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      if (message.type === 'UPDATE_BADGE') {
        const { count, color } = message;
        if (count > 0) {
          await chrome.action.setBadgeText({ text: String(count) });
          await chrome.action.setBadgeBackgroundColor({ color: color || '#EF4444' });
        } else {
          await chrome.action.setBadgeText({ text: 'OK' });
          await chrome.action.setBadgeBackgroundColor({ color: '#10B981' });
        }
        sendResponse({ success: true });
      } else if (message.type === 'SAVE_SCAN') {
        const { scanResult } = message;
        const { scanHistory = [] } = await chrome.storage.local.get('scanHistory');
        
        // Keep max 20 latest scans
        const updatedHistory = [scanResult, ...scanHistory.filter(s => s.url !== scanResult.url)].slice(0, 20);
        await chrome.storage.local.set({ scanHistory: updatedHistory, lastScan: scanResult });
        
        sendResponse({ success: true });
      } else if (message.type === 'GET_LAST_SCAN') {
        const data = await chrome.storage.local.get('lastScan');
        sendResponse({ lastScan: data.lastScan || null });
      }
    } catch (error) {
      console.error('Service worker error:', error);
      sendResponse({ error: error.message });
    }
  })();
  return true; // Keep channel open for async response
});
