const CACHE_DURATION = 3600000; // 1 hour in milliseconds
const DEFAULT_API_KEY = '15a221c1bd813bc72e1a8234ee36fcad9b0b1e3276eb4481a5e46b1b4688cfb5';
const cache = new Map();

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'checkUrl') {
    checkUrlSafety(request.url, request.apiKey || DEFAULT_API_KEY)
      .then(sendResponse)
      .catch(error => sendResponse({ error: error.message }));
    return true; // Required for async response
  }
});

async function checkUrlSafety(url, apiKey) {
  // Check cache first
  const cachedResult = getCachedResult(url);
  if (cachedResult) {
    return cachedResult;
  }

  // Get URL ID from VirusTotal
  const urlId = btoa(url).replace(/=/g, '');

  try {
    // First, submit URL for analysis
    await fetch(`https://www.virustotal.com/api/v3/urls`, {
      method: 'POST',
      headers: {
        'x-apikey': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `url=${encodeURIComponent(url)}`
    });

    // Wait a moment for analysis
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Get analysis results
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: {
        'x-apikey': apiKey
      }
    });

    if (!response.ok) {
      throw new Error('Failed to get analysis results');
    }

    const data = await response.json();
    const result = {
      positives: data.data.attributes.last_analysis_stats.malicious,
      total: data.data.attributes.last_analysis_stats.total,
      scanDate: data.data.attributes.last_analysis_date
    };

    // Cache the result
    cache.set(url, {
      result,
      timestamp: Date.now()
    });

    return result;
  } catch (error) {
    console.error('VirusTotal API error:', error);
    throw new Error('Failed to check URL safety');
  }
}

function getCachedResult(url) {
  const cached = cache.get(url);
  if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
    return cached.result;
  }
  return null;
}
