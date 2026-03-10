/**
 * Platform Registry
 *
 * Central registry for managing all platform adapters.
 * Handles platform registration, detection, and retrieval.
 */
(function initPlatformRegistry(root) {
  const sg = (root.SG = root.SG || {});

  class PlatformRegistry {
    constructor() {
      this.platforms = new Map();
      this.activePlatform = null;
    }

    /**
     * Register a platform adapter
     * @param {BasePlatform} platformClass - The platform class to register
     */
    register(platformClass) {
      try {
        const instance = new platformClass();
        const name = instance.name;

        if (this.platforms.has(name)) {
          console.warn(
            `[MinosVerdictMesh] Platform ${name} is already registered`,
          );
          return;
        }

        this.platforms.set(name, instance);
      } catch (error) {
        console.error(
          `[MinosVerdictMesh] Failed to register platform:`,
          error,
        );
      }
    }

    /**
     * Get a platform by name
     * @param {string} name - The platform name
     * @returns {BasePlatform|null} The platform instance or null
     */
    get(name) {
      return this.platforms.get(name) || null;
    }

    /**
     * Get all registered platforms
     * @returns {Array<BasePlatform>} Array of all platform instances
     */
    getAll() {
      return Array.from(this.platforms.values());
    }

    /**
     * Detect which platform matches the current URL
     * @param {string} url - The URL to check (defaults to window.location.href)
     * @returns {BasePlatform|null} The matching platform or null
     */
    detectPlatform(url = window.location.href) {
      for (const platform of this.platforms.values()) {
        if (platform.matches(url)) {
          console.log(
            `[MinosVerdictMesh] Detected platform: ${platform.displayName}`,
          );
          return platform;
        }
      }

      console.warn(
        `[MinosVerdictMesh] No matching platform found for URL: ${url}`,
      );
      return null;
    }

    /**
     * Set the active platform
     * @param {BasePlatform} platform - The platform to activate
     * @returns {Promise<boolean>} True if activation succeeded
     */
    async activate(platform) {
      if (!platform) {
        console.error("[MinosVerdictMesh] Cannot activate null platform");
        return false;
      }

      // Cleanup previous platform if exists
      if (this.activePlatform && this.activePlatform !== platform) {
        this.activePlatform.cleanup();
      }

      this.activePlatform = platform;

      try {
        // Initialize the platform
        platform.initialize();

        // Wait for platform to be ready
        const ready = await platform.waitForReady();
        if (!ready) {
          console.warn(
            `[MinosVerdictMesh] Platform ${platform.displayName} failed to become ready`,
          );
          return false;
        }

        console.log(
          `[MinosVerdictMesh] Platform ${platform.displayName} activated successfully`,
        );
        return true;
      } catch (error) {
        console.error(
          `[MinosVerdictMesh] Failed to activate platform ${platform.displayName}:`,
          error,
        );
        return false;
      }
    }

    /**
     * Get the currently active platform
     * @returns {BasePlatform|null} The active platform or null
     */
    getActive() {
      return this.activePlatform;
    }

    /**
     * Detect and activate the appropriate platform for the current URL
     * @returns {Promise<BasePlatform|null>} The activated platform or null
     */
    async detectAndActivate() {
      const platform = this.detectPlatform();
      if (!platform) {
        return null;
      }

      const success = await this.activate(platform);
      return success ? platform : null;
    }

    /**
     * Check if a platform is supported
     * @param {string} url - The URL to check
     * @returns {boolean} True if URL is supported
     */
    isSupported(url = window.location.href) {
      return this.detectPlatform(url) !== null;
    }

    /**
     * Get list of supported platform names
     * @returns {Array<string>} Array of platform display names
     */
    getSupportedPlatforms() {
      return Array.from(this.platforms.values()).map((p) => p.displayName);
    }
  }

  // Create singleton instance
  sg.platformRegistry = new PlatformRegistry();
})(typeof window !== "undefined" ? window : globalThis);
