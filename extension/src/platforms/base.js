/**
 * Base Platform Adapter Interface
 *
 * Defines the contract that all platform adapters must follow.
 * Each chatbot platform will have its own adapter that extends this base class.
 */
(function initBasePlatform(root) {
  const sg = (root.SG = root.SG || {});

  class BasePlatform {
    constructor() {
      if (new.target === BasePlatform) {
        throw new TypeError(
          "Cannot construct BasePlatform instances directly - must be extended",
        );
      }
    }

    /**
     * Platform identification
     */
    get name() {
      throw new Error("Platform must implement 'name' getter");
    }

    get displayName() {
      throw new Error("Platform must implement 'displayName' getter");
    }

    get urlPatterns() {
      throw new Error("Platform must implement 'urlPatterns' getter");
    }

    /**
     * Check if current URL matches this platform
     * @param {string} url - The URL to check
     * @returns {boolean} True if URL matches this platform
     */
    matches(url) {
      const patterns = this.urlPatterns;
      return patterns.some((pattern) => {
        if (pattern instanceof RegExp) {
          return pattern.test(url);
        }
        return url.includes(pattern);
      });
    }

    /**
     * DOM Selector Methods - Must be implemented by each platform
     */

    /**
     * Find the text input composer element where users type messages
     * @returns {Element|null} The composer element or null if not found
     */
    findComposer() {
      throw new Error("Platform must implement 'findComposer' method");
    }

    /**
     * Extract text content from the composer element
     * @param {Element} element - The composer element
     * @returns {string} The text content
     */
    getComposerText(element) {
      if (!element) return "";
      if (element.tagName === "TEXTAREA") return element.value;
      // For contenteditable divs, extract text and normalize non-breaking spaces
      return (element.textContent || element.innerText || "").replace(
        /\u00A0/g,
        " ",
      );
    }

    /**
     * Find the send button element
     * @returns {Element|null} The send button or null if not found
     */
    findSendButton() {
      throw new Error("Platform must implement 'findSendButton' method");
    }

    /**
    * Set text content into composer if supported
    */
    setComposerText(element, text) {
      if (!element) return;
      if (element.tagName === "TEXTAREA") {
        element.value = text;
        element.dispatchEvent(new Event("input", { bubbles: true }));
        return;
      }
      if (element.isContentEditable) {
        element.innerText = text;
        element.dispatchEvent(new Event("input", { bubbles: true }));
      }
    }

    /**
     * Platform-specific behavior configuration
     */

    /**
     * Check if a button element is the send button
     * @param {Element} button - The button element to check
     * @returns {boolean} True if this is the send button
     */
    isSendButton(button) {
      if (!button || button.tagName !== "BUTTON") return false;

      // Exclude panel buttons explicitly (applies to all platforms)
      if (button.dataset.sgPanelButton === "true") return false;
      if (button.closest("#sg-llm-panel")) return false;
      if (button.offsetParent === null) return false;

      const expected = this.findSendButton();
      return expected ? button === expected : false;
    }

    /**
     * Custom send logic for platforms with special requirements
     * @param {Element} composer - The composer element
     * @param {Element|null} button - The send button (if available)
     */
    customSendLogic(composer, button) {
      // Default implementation: trigger button click or Enter keypress
      if (button) {
        button.click();
        return;
      }

      const enterEvent = new KeyboardEvent("keydown", {
        key: "Enter",
        code: "Enter",
        keyCode: 13,
        which: 13,
        bubbles: true,
        cancelable: true,
      });
      composer.dispatchEvent(enterEvent);
    }

    /**
     * Find the DOM location where the risk panel should be inserted
     * @returns {Object|null} Object with {host, referenceNode} or null for floating panel
     *   - host: The parent element where the panel should be inserted
     *   - referenceNode: The element to insert before (or null to append to host)
     */
    findPanelInsertionPoint() {
      const composer = this.findComposer();
      if (!composer) return null;

      // Default implementation: insert before form or composer
      const form = composer.closest?.("form");
      const host = form?.parentElement || composer.parentElement;
      if (!host) return null;

      return {
        host: host,
        referenceNode: form || composer,
      };
    }

    /**
     * Initialize platform-specific event listeners or setup
     * Called when the platform is activated
     */
    initialize() {
      // Default: no additional initialization needed
      console.log(
        `[MinosVerdictMesh] Platform initialized: ${this.displayName}`,
      );
    }

    /**
     * Cleanup platform-specific resources
     * Called when switching platforms or unloading
     */
    cleanup() {
      // Default: no cleanup needed
    }

    /**
     * Wait for platform-specific elements to be ready
     * @returns {Promise<boolean>} Resolves to true when ready
     */
    async waitForReady() {
      // Default: wait for composer to appear
      return new Promise((resolve) => {
        const maxAttempts = 50;
        let attempts = 0;

        const check = () => {
          attempts++;
          if (this.findComposer()) {
            resolve(true);
            return;
          }
          if (attempts >= maxAttempts) {
            console.warn(
              `[MinosVerdictMesh] Platform ${this.displayName} not ready after ${maxAttempts} attempts`,
            );
            resolve(false);
            return;
          }
          setTimeout(check, 200);
        };

        check();
      });
    }
  }

  sg.BasePlatform = BasePlatform;
})(typeof window !== "undefined" ? window : globalThis);
