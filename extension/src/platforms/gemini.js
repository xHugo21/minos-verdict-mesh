/**
 * Gemini Platform Adapter
 */
(function initGeminiPlatform(root) {
  const sg = (root.SG = root.SG || {});

  class GeminiPlatform extends sg.BasePlatform {
    get name() {
      return "gemini";
    }

    get displayName() {
      return "Gemini";
    }

    get urlPatterns() {
      return ["gemini.google.com"];
    }

    findComposer() {
      const composer = document.querySelector(
        'div.ql-editor.textarea.new-input-ui[contenteditable="true"]',
      );
      return composer && composer.offsetParent !== null ? composer : null;
    }

    findSendButton() {
      const buttons = document.querySelectorAll("button.send-button.submit");
      for (const btn of buttons) {
        if (btn.offsetParent === null) continue;
        const aria = btn.getAttribute("aria-label")?.toLowerCase() || "";
        const hasIcon = btn.querySelector(
          'mat-icon[fonticon="send"][data-mat-icon-name="send"]',
        );
        if (aria === "send message" || aria === "enviar mensaje" || hasIcon) {
          return btn;
        }
      }

      return null;
    }

    findPanelInsertionPoint() {
      const composer = this.findComposer();
      if (!composer) return null;

      const inputContainer = document.querySelector(".input-area-container");
      if (inputContainer) {
        const inputAreaV2 = inputContainer.querySelector("input-area-v2");
        if (inputAreaV2) {
          return {
            host: inputContainer,
            referenceNode: inputAreaV2,
          };
        }
      }

      return super.findPanelInsertionPoint();
    }

    initialize() {
      console.log(
        "[MinosVerdict] Gemini platform adapter initialized",
      );
    }
  }

  sg.GeminiPlatform = GeminiPlatform;

  if (sg.platformRegistry) {
    sg.platformRegistry.register(GeminiPlatform);
  }
})(typeof window !== "undefined" ? window : globalThis);
