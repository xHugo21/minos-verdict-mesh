/**
 * ChatGPT Platform Adapter
 */
(function initChatGPTPlatform(root) {
  const sg = (root.SG = root.SG || {});

  class ChatGPTPlatform extends sg.BasePlatform {
    get name() {
      return "chatgpt";
    }

    get displayName() {
      return "ChatGPT";
    }

    get urlPatterns() {
      return ["chatgpt.com"];
    }

    findComposer() {
      const composer = document.getElementById("prompt-textarea");
      if (
        composer &&
        composer.classList.contains("ProseMirror") &&
        composer.offsetParent !== null
      ) {
        return composer;
      }
      return null;
    }

    findSendButton() {
      const composer = this.findComposer();
      if (!composer) return null;

      return (
        document.getElementById("composer-submit-button") ||
        document.querySelector('button[data-testid="send-button"]')
      );
    }

    initialize() {
      console.log(
        "[MinosVerdictMesh] ChatGPT platform adapter initialized",
      );
    }
  }

  sg.ChatGPTPlatform = ChatGPTPlatform;

  if (sg.platformRegistry) {
    sg.platformRegistry.register(ChatGPTPlatform);
  }
})(typeof window !== "undefined" ? window : globalThis);
