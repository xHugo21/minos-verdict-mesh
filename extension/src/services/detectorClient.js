(function initDetectorClient(root) {
  const sg = (root.SG = root.SG || {});

  const DEFAULT_ERROR_MESSAGE = "Analysis failed - Backend Unreachable";

  function createDetectorError(message, displayMessage) {
    const err = new Error(message);
    if (displayMessage) err.displayMessage = displayMessage;
    return err;
  }

  function ensureValidResponse(payload) {
    if (!payload || typeof payload !== "object") {
      throw createDetectorError(
        "Invalid detector response",
        "Analysis failed - invalid response.",
      );
    }
    if (payload.error) {
      throw createDetectorError(
        `Detector error: ${payload.error}`,
        "Analysis failed - backend error.",
      );
    }
    if (!("risk_level" in payload) || !Array.isArray(payload.detected_fields)) {
      throw createDetectorError(
        "Invalid detector response",
        "Analysis failed - invalid response.",
      );
    }
    return payload;
  }

  async function requestDetect(formData) {
    let resp;
    try {
      resp = await fetch(`${sg.config.API_BASE}/detect`, {
        method: "POST",
        body: formData,
      });
    } catch (err) {
      throw createDetectorError("Detector unreachable", DEFAULT_ERROR_MESSAGE);
    }
    if (!resp.ok) {
      let detailMessage = "Analysis failed - backend error.";
      try {
        const errorPayload = await resp.json();
        if (errorPayload?.detail && typeof errorPayload.detail === "string") {
          detailMessage = errorPayload.detail;
        }
      } catch {}
      throw createDetectorError(`Detector HTTP ${resp.status}`, detailMessage);
    }
    let payload;
    try {
      payload = await resp.json();
    } catch (err) {
      throw createDetectorError(
        "Invalid detector response",
        "Analysis failed - invalid response.",
      );
    }
    return ensureValidResponse(payload);
  }

  async function detectText(text) {
    const formData = new FormData();
    formData.append("text", text);
    if (sg.config.MIN_BLOCK_LEVEL) {
      formData.append("min_block_level", sg.config.MIN_BLOCK_LEVEL);
    }

    return requestDetect(formData);
  }

  async function detectFile(formData) {
    if (sg.config.MIN_BLOCK_LEVEL && !formData.has("min_block_level")) {
      formData.append("min_block_level", sg.config.MIN_BLOCK_LEVEL);
    }
    return requestDetect(formData);
  }

  function waitForStableContent(node, idleMs = 800) {
    return new Promise((resolve) => {
      let timer = setTimeout(done, idleMs);
      const obs = new MutationObserver(() => {
        clearTimeout(timer);
        timer = setTimeout(done, idleMs);
      });
      function done() {
        obs.disconnect();
        resolve();
      }
      obs.observe(node, {
        childList: true,
        subtree: true,
        characterData: true,
      });
    });
  }

  sg.detectorClient = {
    detectText,
    detectFile,
    waitForStableContent,
  };
})(typeof window !== "undefined" ? window : globalThis);
