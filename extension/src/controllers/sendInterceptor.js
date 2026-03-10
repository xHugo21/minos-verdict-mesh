(function initSendInterceptor(root) {
  const sg = (root.SG = root.SG || {});

  let attached = false;
  let lastSendIntent = null;
  let overrideTimer = null;

  function now() {
    return (root.performance || {}).now ? performance.now() : Date.now();
  }

  function isDetectionEnabled() {
    if (sg.settings?.isDetectionEnabled) {
      return sg.settings.isDetectionEnabled();
    }
    return true;
  }

  function attach() {
    if (attached) return;
    const composer = sg.chatSelectors.findComposer();
    if (!composer) return;
    attached = true;

    sg.panel.ensure();
    sg.highlights.ensureHighlightCSS();
    sg.panel.onSendAnyway(handleSendAnywayOverride);
    sg.panel.onSendSanitized(handleSendSanitized);

    composer.addEventListener("keydown", handleComposerKeydown, true);
    document.addEventListener("click", handleSendButtonClick, true);
  }

  function handleComposerKeydown(event) {
    if (event.key !== "Enter" || event.shiftKey) return;
    if (!isDetectionEnabled()) return;

    // Allow send if override is active
    if (sg.alertStore.isOverrideActive()) return;

    const composer = sg.chatSelectors.findComposer();
    if (!composer) return;
    const text = sg.chatSelectors.getComposerText(composer);
    if (!text) return;

    event.preventDefault();
    event.stopPropagation();
    analyzeBeforeSend({ composer, text });
  }

  function handleSendButtonClick(event) {
    // Check if clicked element or its closest button ancestor is the send button
    const clickedButton =
      event.target.tagName === "BUTTON"
        ? event.target
        : event.target.closest("button");

    if (!clickedButton) return;

    // Use platform-specific button detection
    const platform = sg.platformRegistry?.getActive();
    if (!platform || !platform.isSendButton(clickedButton)) return;
    if (!isDetectionEnabled()) return;

    // Allow send if override is active or bypass flag is set
    if (clickedButton.dataset.sgBypass === "true") return;
    if (sg.alertStore.isOverrideActive()) return;

    const composer = sg.chatSelectors.findComposer();
    if (!composer) return;
    const text = sg.chatSelectors.getComposerText(composer);
    if (!text) return;

    event.preventDefault();
    event.stopImmediatePropagation();
    analyzeBeforeSend({ composer, button: clickedButton, text });
  }

  async function analyzeBeforeSend({ composer, button = null, text }) {
    const startedAt = now();
    let panelShown = false;
    let backendError = null;
    lastSendIntent = null;
    const loadingTarget = {
      composer,
      button: button || sg.chatSelectors.findSendButton(),
      message: "Analyzing message...",
    };
    sg.loadingState.show(loadingTarget);
    try {
      const result = await sg.detectorClient.detectText(text);
      sg.highlights.applyHighlights(
        composer,
        result?.detected_fields || [],
        "user",
      );
      lastSendIntent = {
        composer,
        button,
        originalText: text,
        detectionResult: result,
      };

      if (sg.riskUtils.shouldBlock(result)) {
        const durationMs = now() - startedAt;
        sg.panel.render(result, text, { durationMs, mode: "block" });
        panelShown = true;
        return;
      }

      if (sg.riskUtils.shouldWarn(result)) {
        const durationMs = now() - startedAt;
        sg.panel.render(result, text, { durationMs, mode: "warn" });
        panelShown = true;

        setTimeout(() => {
          allowSend(composer, button);
        }, 50);
        return;
      }

      allowSend(composer, button);
    } catch (err) {
      backendError = err;
      console.error(
        "[MinosVerdictMeshExtension] Backend error, blocking send:",
        err,
      );
    } finally {
      const durationMs = now() - startedAt;
      sg.loadingState.hide({ durationMs, panelShown, error: backendError });
    }
  }

  function allowSend(composer, button) {
    setTimeout(() => sg.highlights.clearHighlights("user"), 50);
    dispatchSend(composer, button);
    lastSendIntent = null;
  }

  function dispatchSend(composer, button, overrideText) {
    const sendButton = button || sg.chatSelectors.findSendButton?.();

    if (overrideText && sg.chatSelectors.setComposerText) {
      sg.chatSelectors.setComposerText(composer, overrideText);
    }

    if (sendButton) {
      sendButton.disabled = false;
      sendButton.removeAttribute("aria-disabled");
      sendButton.removeAttribute("aria-busy");
    }

    sg.alertStore.setOverrideActive(true);

    const sendDelay = overrideText ? 50 : 0;

    setTimeout(() => {
      try {
        sg.chatSelectors.triggerSend(composer, sendButton);
      } finally {
        setTimeout(() => sg.alertStore.setOverrideActive(false), 150);
      }
    }, sendDelay);
  }

  function handleSendAnywayOverride() {
    if (!lastSendIntent) {
      sg.panel.hide();
      return;
    }

    sg.alertStore.setOverrideActive(true);
    sg.panel.hide();
    dispatchSend(lastSendIntent.composer, lastSendIntent.button);
    setTimeout(() => sg.alertStore.setOverrideActive(false), 1500);
    lastSendIntent = null;
  }

  function handleSendSanitized() {
    if (!lastSendIntent) {
      sg.panel.hide();
      return;
    }
    const sanitized =
      lastSendIntent.detectionResult?.anonymized_text ||
      lastSendIntent.originalText;

    sg.alertStore.setOverrideActive(true);
    sg.panel.hide();
    dispatchSend(lastSendIntent.composer, lastSendIntent.button, sanitized);
    setTimeout(() => sg.alertStore.setOverrideActive(false), 1500);
    lastSendIntent = null;
  }

  sg.sendInterceptor = { attach };
})(typeof window !== "undefined" ? window : globalThis);
