/**
 * anchor.js v2.0
 * Anchor Security SDK
 * Identity & Session Protection Platform
 * SS26Hack 2026 - ITWeb Security Summit
 *
 * Usage:
 * <script src="anchor.js"></script>
 * <script>
 *   const anchor = new AnchorSDK('your-api-key', 'https://your-anchor-url');
 *
 *   // On registration:
 *   await anchor.register(userId);
 *
 *   // On login:
 *   const result = await anchor.login(userId);
 *   if (result.status === 'ok') {
 *     // proceed with login
 *   }
 *
 *   // After login — protect the session:
 *   await anchor.protect(sessionToken);
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
  // DEVICE DATA COLLECTION
  // Real browser fingerprinting
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

  getWebGLFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return 'webgl-not-supported';
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      if (!debugInfo) return 'webgl-no-debug';
      const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
      const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
      return `${vendor}::${renderer}`;
    } catch (e) {
      return 'webgl-blocked';
    }
  }

  collectDeviceData() {
    return {
      canvas_hash: this.getCanvasHash(),
      webgl: this.getWebGLFingerprint(),
      screen_resolution: `${screen.width}x${screen.height}`,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      language: navigator.language,
      hardware_concurrency: navigator.hardwareConcurrency || 0,
      platform: navigator.platform,
      user_agent: navigator.userAgent
    };
  }

  // ─────────────────────────────────────────
  // WEBAUTHN - REAL CHIP LEVEL VERIFICATION
  // Talks to TPM / Secure Enclave / TrustZone
  // Private key NEVER leaves the chip
  // ─────────────────────────────────────────

  async webauthnSupported() {
    return window.PublicKeyCredential !== undefined;
  }

  async registerWebAuthn(userId, challenge) {
    /**
     * Registers the device's chip with Anchor.
     * Called once at account creation.
     *
     * The chip generates a keypair:
     * - Private key stays on chip forever
     * - Public key sent to Anchor API
     */
    try {
      if (!await this.webauthnSupported()) {
        return { supported: false, reason: 'WebAuthn not supported on this device' };
      }

      const challengeBuffer = Uint8Array.from(
        atob(challenge.replace(/-/g, '+').replace(/_/g, '/')),
        c => c.charCodeAt(0)
      );

      const userIdBuffer = new TextEncoder().encode(userId);

      // Ask the chip to generate a keypair
      const credential = await navigator.credentials.create({
        publicKey: {
          challenge: challengeBuffer,
          rp: {
            name: "Anchor Security",
            id: window.location.hostname
          },
          user: {
            id: userIdBuffer,
            name: userId,
            displayName: userId
          },
          pubKeyCredParams: [
            { alg: -7, type: "public-key" },   // ES256
            { alg: -257, type: "public-key" }  // RS256
          ],
          authenticatorSelection: {
            authenticatorAttachment: "platform", // uses built-in TPM/Enclave
            userVerification: "preferred"
          },
          timeout: 60000,
          attestation: "none"
        }
      });

      // Extract the credential data
      const credentialId = btoa(String.fromCharCode(
        ...new Uint8Array(credential.rawId)
      ));

      const publicKey = btoa(String.fromCharCode(
        ...new Uint8Array(credential.response.getPublicKey
          ? credential.response.getPublicKey()
          : credential.response.attestationObject)
      ));

      return {
        supported: true,
        credential_id: credentialId,
        public_key: publicKey,
        device_type: 'platform'
      };

    } catch (e) {
      console.warn('[Anchor WebAuthn] Registration failed:', e.message);
      return { supported: true, chip_verified: false, reason: e.message };
    }
  }

  async verifyWebAuthn(userId, challenge) {
    /**
     * Verifies the device chip on login.
     * Anchor sends a challenge → chip signs it → Anchor verifies.
     * Physical device MUST be present.
     */
    try {
      if (!await this.webauthnSupported()) {
        return { supported: false, reason: 'WebAuthn not supported' };
      }

      const challengeBuffer = Uint8Array.from(
        atob(challenge.replace(/-/g, '+').replace(/_/g, '/')),
        c => c.charCodeAt(0)
      );

      // Ask the chip to sign the challenge
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: challengeBuffer,
          rpId: window.location.hostname,
          userVerification: "preferred",
          timeout: 60000
        }
      });

      const credentialId = btoa(String.fromCharCode(
        ...new Uint8Array(assertion.rawId)
      ));

      const signature = btoa(String.fromCharCode(
        ...new Uint8Array(assertion.response.signature)
      ));

      const authenticatorData = btoa(String.fromCharCode(
        ...new Uint8Array(assertion.response.authenticatorData)
      ));

      return {
        supported: true,
        chip_verified: true,
        credential_id: credentialId,
        signature: signature,
        authenticator_data: authenticatorData
      };

    } catch (e) {
      console.warn('[Anchor WebAuthn] Verification failed:', e.message);
      return { supported: true, chip_verified: false, reason: e.message };
    }
  }

  // ─────────────────────────────────────────
  // ANCHOR API CALLS
  // ─────────────────────────────────────────

  async _post(endpoint, body) {
    try {
      const response = await fetch(`${this.anchorUrl}${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.apiKey
        },
        body: JSON.stringify(body)
      });
      return await response.json();
    } catch (e) {
      console.error(`[Anchor] API call failed (${endpoint}):`, e);
      return { status: 'error', message: e.message };
    }
  }

  async _get(endpoint) {
    try {
      const response = await fetch(`${this.anchorUrl}${endpoint}`, {
        headers: { 'x-api-key': this.apiKey }
      });
      return await response.json();
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  }

  // ─────────────────────────────────────────
  // REGISTER — Call at account creation
  // ─────────────────────────────────────────

  async register(userId) {
    console.log('[Anchor] Starting registration for:', userId);
    const device = this.collectDeviceData();

    // Step 1 — Register device fingerprint
    const identityResult = await this._post('/identity/register', {
      user_id: userId,
      canvas_hash: device.canvas_hash,
      screen_resolution: device.screen_resolution,
      timezone: device.timezone,
      hardware_concurrency: device.hardware_concurrency,
      language: device.language,
      webgl: device.webgl,
      platform: device.platform,
      ip_address: 'client-side'
    });

    console.log('[Anchor] Identity registered — DID:', identityResult.did);

    // Step 2 — Register WebAuthn (TPM/Secure Enclave)
    if (await this.webauthnSupported()) {
      try {
        const challengeResult = await this._post('/webauthn/challenge', {
          user_id: userId
        });

        const webauthnResult = await this.registerWebAuthn(
          userId,
          challengeResult.challenge
        );

        if (webauthnResult.chip_verified !== false && webauthnResult.credential_id) {
          const regResult = await this._post('/webauthn/register', {
            user_id: userId,
            credential_id: webauthnResult.credential_id,
            public_key: webauthnResult.public_key,
            challenge: challengeResult.challenge,
            device_type: webauthnResult.device_type || 'platform'
          });
          console.log('[Anchor] WebAuthn registered:', regResult.message);
        }
      } catch (e) {
        console.warn('[Anchor] WebAuthn registration skipped:', e.message);
      }
    }

    return {
      status: 'ok',
      message: 'Device registered with Anchor',
      did: identityResult.did
    };
  }

  // ─────────────────────────────────────────
  // LOGIN — Call before granting access
  // ─────────────────────────────────────────

  async login(userId) {
    console.log('[Anchor] Verifying login for:', userId);
    const device = this.collectDeviceData();

    // Step 1 — Verify device fingerprint
    const identityResult = await this._post('/identity/verify-login', {
      user_id: userId,
      canvas_hash: device.canvas_hash,
      screen_resolution: device.screen_resolution,
      timezone: device.timezone,
      hardware_concurrency: device.hardware_concurrency,
      language: device.language,
      webgl: device.webgl,
      platform: device.platform,
      ip_address: 'client-side'
    });

    console.log('[Anchor] Identity check:', identityResult.status, '| Risk:', identityResult.risk?.level);

    if (identityResult.status === 'threat') {
      return {
        status: 'threat',
        message: identityResult.message,
        risk: identityResult.risk,
        action: 'block'
      };
    }

    // Step 2 — WebAuthn chip verification
    if (await this.webauthnSupported()) {
      try {
        const challengeResult = await this._post('/webauthn/challenge', {
          user_id: userId
        });

        const webauthnResult = await this.verifyWebAuthn(
          userId,
          challengeResult.challenge
        );

        if (webauthnResult.chip_verified) {
          const verifyResult = await this._post('/webauthn/verify', {
            user_id: userId,
            credential_id: webauthnResult.credential_id,
            signature: webauthnResult.signature,
            challenge: challengeResult.challenge,
            authenticator_data: webauthnResult.authenticator_data
          });
          console.log('[Anchor] WebAuthn:', verifyResult.message);
        }
      } catch (e) {
        console.warn('[Anchor] WebAuthn login skipped:', e.message);
      }
    }

    return {
      status: identityResult.status,
      message: identityResult.message,
      did: identityResult.did,
      risk: identityResult.risk,
      action: identityResult.action || 'allow'
    };
  }

  // ─────────────────────────────────────────
  // PROTECT — Call after login
  // Starts continuous session monitoring
  // ─────────────────────────────────────────

  async protect(token) {
    this.sessionToken = token;
    console.log('[Anchor] Session protection active');

    // Immediate device verification
    const deviceResult = await this.verifyDevice(token);
    console.log('[Anchor] Device check:', deviceResult.status, '| Risk:', deviceResult.risk?.level);

    if (deviceResult.status === 'threat') {
      this.onThreat(deviceResult);
      return;
    }

    // Monitor every 60 seconds
    this.verificationInterval = setInterval(async () => {
      const check = await this.verifyDevice(token);
      if (check.status === 'threat') {
        this.onThreat(check);
        this.stop();
      }
    }, 60000);
  }

  async verifyDevice(token) {
    const device = this.collectDeviceData();
    return await this._post('/session/verify-device', {
      token: token,
      canvas_hash: device.canvas_hash,
      screen_resolution: device.screen_resolution,
      timezone: device.timezone,
      hardware_concurrency: device.hardware_concurrency,
      language: device.language
    });
  }

  async validateSession(token) {
    return await this._post('/session/validate', {
      token: token,
      ip_address: 'client-side',
      user_agent: navigator.userAgent
    });
  }

  // ─────────────────────────────────────────
  // THREAT HANDLER
  // Override this to customize behavior
  // ─────────────────────────────────────────

  onThreat(result) {
    console.error('[Anchor] THREAT:', result.message);
    alert(`[Anchor Security] Session terminated.\nReason: ${result.message}\nRisk: ${result.risk?.level?.toUpperCase()}`);
    window.location.href = '/login';
  }

  stop() {
    if (this.verificationInterval) {
      clearInterval(this.verificationInterval);
      this.verificationInterval = null;
    }
  }
}

window.AnchorSDK = AnchorSDK;
console.log('[Anchor] anchor.js v2.0 loaded — Identity & Session Protection');