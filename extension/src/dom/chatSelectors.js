/**
 * Chat Selectors
 *
 * This module allows delegating all DOM selector operations to the currently active platform adapter.
 * This allows the extension to work across different chatbot platforms
 */
(function initChatSelectors(root) {
  const sg = (root.SG = root.SG || {});

  function getActivePlatform() {
    const platform = sg.platformRegistry?.getActive();
    if (!platform) {
      console.warn("[MinosVerdict] No active platform found");
    }
    return platform;
  }

  function findComposer() {
    const platform = getActivePlatform();
    return platform ? platform.findComposer() : null;
  }

  function getComposerText(el) {
    const platform = getActivePlatform();
    return platform ? platform.getComposerText(el) : "";
  }

  function setComposerText(el, text) {
    const platform = getActivePlatform();
    if (platform && typeof platform.setComposerText === "function") {
      platform.setComposerText(el, text);
    }
  }

  function findSendButton() {
    const platform = getActivePlatform();
    return platform ? platform.findSendButton() : null;
  }

  function triggerSend(composer, button) {
    const platform = getActivePlatform();
    if (platform) {
      platform.customSendLogic(composer, button);
    }
  }

  sg.chatSelectors = {
    findComposer,
    getComposerText,
    setComposerText,
    findSendButton,
    triggerSend,
  };
})(typeof window !== "undefined" ? window : globalThis);
