/**
 * PhishGuard API Service
 * All communication with the backend API.
 */

const API_BASE = '/api';

// Human-readable messages for OAuth error codes returned by the backend
// via /settings?error=<code> after the Google OAuth callback.
const OAUTH_ERROR_MESSAGES = {
  access_denied: 'You cancelled the Google sign-in or denied the requested permissions.',
  admin_policy_enforced: 'Your Google Workspace organization does not allow this application.',
  org_internal: 'This Google OAuth client is restricted to organization-internal users.',
  missing_code: 'Google did not return an authorization code. Please try again.',
  invalid_state: 'The sign-in session expired or failed a security check. Please try again.',
  token_exchange_failed: 'Google rejected the authorization code exchange. Verify the OAuth client configuration in backend/.env and Google Cloud Console.',
  network_error: 'Network error while contacting Google. Check your connection and try again.',
  gmail_api_disabled: 'The Gmail API is not enabled for this Google Cloud project.',
  profile_failed: 'Could not read your Gmail profile after sign-in.',
};
const GENERIC_OAUTH_ERROR = 'Gmail authorization failed. Please try again.';

class ApiService {
  // ── Email Analysis ──

  async analyzeEml(file) {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch(`${API_BASE}/analyze/eml`, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Upload failed' }));
      throw new Error(error.detail || 'Failed to analyze email');
    }

    return response.json();
  }

  async getEmails(skip = 0, limit = 100) {
    const response = await fetch(`${API_BASE}/emails?skip=${skip}&limit=${limit}`);
    if (!response.ok) throw new Error('Failed to fetch emails');
    return response.json();
  }

  async getEmailAnalysis(id) {
    const response = await fetch(`${API_BASE}/emails/${id}`);
    if (!response.ok) {
      if (response.status === 404) throw new Error('Unable to load email. This analysis no longer exists.');
      throw new Error('Unable to load email. Please try again.');
    }
    return response.json();
  }

  async getStatistics() {
    const response = await fetch(`${API_BASE}/statistics`);
    if (!response.ok) throw new Error('Failed to fetch statistics');
    return response.json();
  }

  async deleteEmail(id) {
    const response = await fetch(`${API_BASE}/emails/${id}`, { method: 'DELETE' });
    if (!response.ok) throw new Error('Failed to delete analysis');
    return response.json();
  }

  // ── Gmail Integration ──

  async getGmailStatus() {
    const response = await fetch(`${API_BASE}/gmail/status`, {
      credentials: 'include',
    });
    if (!response.ok) return { connected: false, email: null, last_sync: null };
    return response.json();
  }

  // ── AI Verification (optional second opinion) ──

  async getAIStatus() {
    const response = await fetch(`${API_BASE}/ai/status`);
    if (!response.ok) return { configured: false, model: null };
    return response.json();
  }

  async verifyWithAI(analysisId) {
    const response = await fetch(`${API_BASE}/ai/verify/${analysisId}`, {
      method: 'POST',
    });
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.detail || 'AI verification failed');
    }
    return response.json();
  }

  async syncGmail(maxResults = 50) {
    const response = await fetch(`${API_BASE}/gmail/sync?max_results=${maxResults}`, {
      method: 'POST',
      credentials: 'include',
    });
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Sync failed' }));
      throw new Error(error.detail || 'Failed to sync Gmail');
    }
    return response.json();
  }

  async analyzeGmailMessage(messageId) {
    const response = await fetch(`${API_BASE}/gmail/analyze-single?message_id=${messageId}`, {
      method: 'POST',
      credentials: 'include',
    });
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Analysis failed' }));
      throw new Error(error.detail || 'Failed to analyze Gmail message');
    }
    return response.json();
  }

  /**
   * Fetch body content for an older analyzed email whose body was not
   * stored. Uses the existing server-side Gmail session. Returns
   * { available, cached, body_text, body_html } or
   * { available: false, message } when Gmail is unavailable.
   */
  async getGmailMessageContent(analysisId) {
    const response = await fetch(`${API_BASE}/gmail/message-content/${analysisId}`, {
      credentials: 'include',
    });
    if (response.status === 401) {
      throw new Error('Gmail session expired. Please reconnect your account in Settings.');
    }
    if (response.status === 404) {
      throw new Error('Unable to load email. This analysis no longer exists.');
    }
    if (!response.ok) {
      throw new Error('Email content is currently unavailable. The stored security analysis is still available.');
    }
    return response.json();
  }

  async startGmailPolling() {
    const response = await fetch(`${API_BASE}/gmail/start-polling`, {
      method: 'POST',
      credentials: 'include',
    });
    return response.json();
  }

  async stopGmailPolling() {
    const response = await fetch(`${API_BASE}/gmail/stop-polling`, {
      method: 'POST',
    });
    return response.json();
  }

  // ── OAuth ──

  connectGmail() {
    window.location.href = '/auth/google';
  }

  async disconnectGmail() {
    const response = await fetch('/auth/google/disconnect', {
      method: 'POST',
      credentials: 'include',
    });
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.detail || 'Failed to disconnect Gmail');
    }
    return response.json();
  }

  // Map an OAuth error code from the callback URL to a user-facing message.
  explainOAuthError(code) {
    return OAUTH_ERROR_MESSAGES[code] || GENERIC_OAUTH_ERROR;
  }

  // ── Health ──

  async healthCheck() {
    const response = await fetch(`${API_BASE}/health`);
    return response.json();
  }

  // ── MailBuddy ──

  async getMailBuddySettings() {
    const response = await fetch(`${API_BASE}/mailbuddy/settings`);
    if (!response.ok) throw new Error('Failed to fetch MailBuddy settings');
    return response.json();
  }

  async updateMailBuddySettings(patch) {
    const response = await fetch(`${API_BASE}/mailbuddy/settings`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch),
    });
    if (!response.ok) throw new Error('Failed to update MailBuddy settings');
    return response.json();
  }

  async getPrioritySummary() {
    const response = await fetch(`${API_BASE}/mailbuddy/priority/summary`);
    if (!response.ok) throw new Error('Failed to fetch priority summary');
    return response.json();
  }

  async getPriorityEmails(level, category) {
    const params = new URLSearchParams();
    if (level) params.set('level', level);
    if (category) params.set('category', category);
    const response = await fetch(`${API_BASE}/mailbuddy/priority/emails?${params}`);
    if (!response.ok) throw new Error('Failed to fetch priority emails');
    return response.json();
  }

  async analyzeBatchPriorities(limit = 10) {
    const response = await fetch(`${API_BASE}/mailbuddy/priority/analyze-batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ limit }),
    });
    if (!response.ok) throw new Error('Priority batch analysis failed');
    return response.json();
  }

  async askMailBuddy(question) {
    const response = await fetch(`${API_BASE}/mailbuddy/assistant/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question }),
    });
    if (!response.ok) throw new Error('Assistant request failed');
    return response.json();
  }

  async getPendingNotifications() {
    const response = await fetch(`${API_BASE}/mailbuddy/notifications/pending`);
    if (!response.ok) return { enabled: false, notifications: [] };
    return response.json();
  }

  async acknowledgeNotifications(keys) {
    const response = await fetch(`${API_BASE}/mailbuddy/notifications/ack`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ keys }),
    });
    if (!response.ok) return { marked: 0 };
    return response.json();
  }
}

export const api = new ApiService();
export default api;
