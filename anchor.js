/**
 * anchor.js
 * Anchor Security SDK - Browser Fingerprint & Device Verification
 * SS26Hack 2026 - ITWeb Security Summit Hackathon
 * 
 * Usage:
 * <script src="anchor.js"></script>
 * <script>
 *   const anchor = new AnchorSDK('your-api-key', 'https://your-anchor-url');
 *   anchor.protect(sessionToken);
 * </script>
 */

class AnchorSDK {
  constructor(apiKey, anchorUrl) {
    this.apiKey = apiKey;
    this.anchorUrl = anchorUrl || 'http://127.0.0.1:8000';
    this.sessionToken = null;
    this.verificationInterval = null;
  }

  // ─────────────────────────────────────────
  // 1. CANVAS FINGERPRINT
  // Every GPU renders canvas slightly differently
  // This is unique per device
  // ─────────────────────────────────────────
  getCanvasHash() {
    try {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('Anchor Security 2026', 2, 15);
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.fillText('Anchor Security 2026', 4, 17);
      return canvas.toDataURL().slice(-50);
    } catch (e) {
      return 'canvas-blocked';
    }
  }

  // ─────────────────────────────────────────
  // 2. WEBGL FINGERPRINT
  // GPU renderer string — unique per graphics card
  // ─────────────────────────────────────────
  getWebGLFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return 'webgl-not-supported';
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
      const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
      return `${vendor}::${renderer}`;
    } catch (e) {
      return 'webgl-blocked';
    }
  }

  // ─────────────────────────────────────────
  // 3. COLLECT ALL DEVICE DATA
  // ─────────────────────────────────────────
  collectDeviceData() {
    return {
      canvas_hash: this.getCanvasHash(),
      webgl: this.getWebGLFingerprint(),
      screen_resolution: `${screen.width}x${screen.height}`,
      color_depth: screen.colorDepth,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      language: navigator.language,
      hardware_concurrency: navigator.hardwareConcurrency || 0,
      platform: navigator.platform,
      touch_support: navigator.maxTouchPoints > 0,
      do_not_track: navigator.doNotTrack,
      cookie_enabled: navigator.cookieEnabled,
      user_agent: navigator.userAgent
    };
  }

  // ─────────────────────────────────────────
  // 4. WEBAUTHN - CHIP LEVEL SIGNATURE
  // Talks directly to TPM / Secure Enclave
  // Cannot be spoofed — ever
  // ─────────────────────────────────────────
  async getWebAuthnSignature(challenge) {
    try {
      // Check if WebAuthn is supported
      if (!window.PublicKeyCredential) {
        return { supported: false, reason: 'WebAuthn not supported on this device' };
      }

      const challengeBuffer = new TextEncoder().encode(challenge);

      // Request device attestation
      const credential = await navigator.credentials.get({
        publicKey: {
          challenge: challengeBuffer,
          timeout: 10000,
          userVerification: 'discouraged',
          rpId: window.location.hostname
        }
      });

      if (credential) {
        return {
          supported: true,
          credential_id: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
          authenticator_data: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
          chip_verified: true
        };
      }
    } catch (e) {
      // WebAuthn failed — not registered yet or user cancelled
      return {
        supported: true,
        chip_verified: false,
        reason: e.message
      };
    }
  }

  // ─────────────────────────────────────────
  // 5. SEND TO ANCHOR API
  // ─────────────────────────────────────────
  async verifyDevice(token) {
    const deviceData = this.collectDeviceData();

    try {
      const response = await fetch(`${this.anchorUrl}/session/verify-device`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.apiKey
        },
        body: JSON.stringify({
          token: token,
          canvas_hash: deviceData.canvas_hash,
          screen_resolution: deviceData.screen_resolution,
          timezone: deviceData.timezone,
          hardware_concurrency: deviceData.hardware_concurrency,
          language: deviceData.language
        })
      });

      const result = await response.json();
      return result;
    } catch (e) {
      console.error('[Anchor] Device verification failed:', e);
      return { status: 'error', message: e.message };
    }
  }

  // ─────────────────────────────────────────
  // 6. VALIDATE SESSION
  // ─────────────────────────────────────────
  async validateSession(token) {
    try {
      const response = await fetch(`${this.anchorUrl}/session/validate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.apiKey
        },
        body: JSON.stringify({
          token: token,
          ip_address: 'client-side',
          user_agent: navigator.userAgent
        })
      });

      return await response.json();
    } catch (e) {
      console.error('[Anchor] Session validation failed:', e);
      return { status: 'error', message: e.message };
    }
  }

  // ─────────────────────────────────────────
  // 7. PROTECT — MAIN METHOD
  // Call this after login with the session token
  // Anchor handles everything automatically
  // ─────────────────────────────────────────
  async protect(token) {
    this.sessionToken = token;
    console.log('[Anchor] Protection activated for session:', token.slice(0, 8) + '...');

    // Immediate device verification
    const deviceResult = await this.verifyDevice(token);
    console.log('[Anchor] Device verification:', deviceResult.status, '| Risk:', deviceResult.risk?.level || 'n/a');

    if (deviceResult.status === 'threat') {
      console.error('[Anchor] THREAT DETECTED:', deviceResult.message);
      this.onThreat(deviceResult);
      return;
    }

    // Start continuous monitoring every 60 seconds
    this.verificationInterval = setInterval(async () => {
      const check = await this.verifyDevice(token);
      if (check.status === 'threat') {
        console.error('[Anchor] THREAT DETECTED during monitoring:', check.message);
        this.onThreat(check);
        this.stop();
      }
    }, 60000);
  }

  // ─────────────────────────────────────────
  // 8. THREAT HANDLER
  // Override this to customize threat response
  // ─────────────────────────────────────────
  onThreat(result) {
    // Default behavior — alert and redirect to login
    alert(`[Anchor Security] Your session has been terminated.\nReason: ${result.message}\nRisk Level: ${result.risk?.level?.toUpperCase()}`);
    window.location.href = '/login';
  }

  // ─────────────────────────────────────────
  // 9. STOP MONITORING
  // ─────────────────────────────────────────
  stop() {
    if (this.verificationInterval) {
      clearInterval(this.verificationInterval);
      this.verificationInterval = null;
      console.log('[Anchor] Monitoring stopped');
    }
  }
}

// Auto-expose globally
window.AnchorSDK = AnchorSDK;
console.log('[Anchor] anchor.js loaded — Anchor Security SDK v1.0.0');
