(function initFileInterceptor(root) {
  const sg = (root.SG = root.SG || {});
  let attached = false;
  let lastFileIntent = null;

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
    attached = true;
    document.addEventListener("change", handleFileChange, true);
    sg.panel.onSendAnyway(handleUploadAnyway);
    sg.panel.onSendSanitized(handleSendSanitized);
    sg.panel.onDismiss(handleDismiss);
    console.log(
      "[SensitiveDataDetectorExtension] File interceptor attached - monitoring all file uploads",
    );
  }

  function consumeBypassFlag(input) {
    if (!input || !input.dataset) return false;
    if (input.dataset.sgBypass !== "true") return false;
    delete input.dataset.sgBypass;
    return true;
  }

  function allowUpload(input, files) {
    if (!input) return;

    try {
      const dataTransfer = new DataTransfer();
      if (Array.isArray(files)) {
        files.forEach((file) => dataTransfer.items.add(file));
      }
      if (dataTransfer.files?.length) {
        try {
          input.files = dataTransfer.files;
        } catch (err) {
          console.warn(
            "[SensitiveDataDetectorExtension] Could not reset file input files:",
            err,
          );
        }
      }
    } catch (err) {
      console.warn(
        "[SensitiveDataDetectorExtension] Could not rebuild file list:",
        err,
      );
    }

    if (input.dataset) {
      input.dataset.sgBypass = "true";
    }
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function clearInput(input) {
    if (!input) return;
    try {
      input.value = "";
    } catch (err) {
      // Ignore if browser prevents programmatic clearing.
    }
  }

  function sendSanitizedText(text) {
    if (!text) return false;
    const composer = sg.chatSelectors?.findComposer?.();
    if (!composer) return false;
    const button = sg.chatSelectors?.findSendButton?.();

    if (sg.chatSelectors?.setComposerText) {
      sg.chatSelectors.setComposerText(composer, text);
    }

    sg.alertStore.setOverrideActive(true);
    setTimeout(() => {
      try {
        sg.chatSelectors?.triggerSend?.(composer, button);
      } finally {
        setTimeout(() => sg.alertStore.setOverrideActive(false), 150);
      }
    }, 50);
    return true;
  }

  function shouldBlockFile(result) {
    if (!result) return false;
    const decision = String(result.decision || "").toLowerCase();
    if (decision === "block") return true;
    return result.risk_level === "high";
  }

  function shouldWarnFile(result) {
    if (!result) return false;
    const decision = String(result.decision || "").toLowerCase();
    return decision === "warn";
  }

  async function handleFileChange(event) {
    const input = event.target;
    if (!input || input.type !== "file" || !input.files?.length) return;
    if (!isDetectionEnabled()) {
      consumeBypassFlag(input);
      return;
    }

    if (consumeBypassFlag(input)) return;

    const files = Array.from(input.files || []);
    if (!files.length) return;

    const inFlight = sg.alertStore.isInFlight(input);
    if (!inFlight && files.length === 0) return;

    event.preventDefault();
    event.stopImmediatePropagation();

    if (inFlight) return;

    sg.alertStore.beginInFlight(input);

    const startedAt = now();
    let durationMs = 0;
    let panelShown = false;
    let loadingShown = false;
    let backendError = null;

    try {
      console.log(
        `[SensitiveDataDetectorExtension] Detected ${files.length} file upload(s): ${files.map((f) => f.name).join(", ")}`,
      );

      // Show loading state
      sg.loadingState.show({
        message:
          files.length > 1
            ? `Analyzing ${files.length} files...`
            : "Analyzing file...",
      });
      loadingShown = true;

      const result = await sg.fileAnalyzer.analyzeFiles(files);

      if (result?.extracted_snippet) {
        console.log(
          `[SensitiveDataDetectorExtension] Extracted snippet from ${files.length} file(s):`,
          result.extracted_snippet.substring(0, 200) + "...",
        );
      }
      if (result?.detected_fields?.length > 0) {
        console.log(
          `[SensitiveDataDetectorExtension] Detected ${result.detected_fields.length} sensitive field(s) across ${files.length} file(s):`,
          result.detected_fields.map((f) => f.field),
        );
      }

      durationMs = now() - startedAt;

      if (shouldBlockFile(result)) {
        const displayName =
          files.length === 1 ? files[0].name : `${files.length} files`;
        const sanitizedText =
          typeof result?.anonymized_text === "string"
            ? result.anonymized_text.trim()
            : "";
        lastFileIntent = {
          input,
          files,
          result: result,
          sanitizedText: sanitizedText || null,
        };
        sg.panel.render(result, displayName, {
          durationMs,
          mode: "block",
          requireAction: true,
          primaryActionLabel: "Upload anyway",
        });
        panelShown = true;
        clearInput(input);
        return;
      }

      if (shouldWarnFile(result)) {
        const displayName =
          files.length === 1 ? files[0].name : `${files.length} files`;
        allowUpload(input, files);
        sg.panel.render(result, displayName, {
          durationMs,
          mode: "warn",
          requireAction: false,
          hideSanitized: true,
        });
        panelShown = true;
        return;
      }

      allowUpload(input, files);
    } catch (err) {
      backendError = err;
      durationMs = now() - startedAt;
      const displayName =
        files.length === 1 ? files[0].name : `${files.length} files`;
      console.error(
        `[SensitiveDataDetectorExtension] Error analyzing ${displayName}:`,
        err,
      );

      const errorMessage = err.displayMessage || err.message || "Unknown error";

      sg.panel.render(
        {
          risk_level: "unknown",
          detected_fields: [],
          error: errorMessage,
        },
        displayName,
        {
          durationMs,
          mode: "warn",
          requireAction: true,
          primaryActionLabel: "Upload anyway",
          hideSanitized: true,
        },
      );
      panelShown = true;
      lastFileIntent = {
        input,
        files,
        error: err,
      };
      clearInput(input);
    } finally {
      sg.alertStore.endInFlight(input);
      if (loadingShown) {
        sg.loadingState.hide({ durationMs, panelShown, error: backendError });
      }
    }
  }

  function handleUploadAnyway() {
    if (!lastFileIntent) return;
    const { input, files } = lastFileIntent;
    sg.panel.hide();
    allowUpload(input, files);
    lastFileIntent = null;
  }

  function handleSendSanitized() {
    if (!lastFileIntent) return;
    const { sanitizedText, input } = lastFileIntent;
    sg.panel.hide();
    if (sanitizedText) {
      sendSanitizedText(sanitizedText);
      clearInput(input);
    }
    lastFileIntent = null;
  }

  function handleDismiss() {
    if (!lastFileIntent) return;
    lastFileIntent = null;
  }

  sg.fileInterceptor = { attach };
})(typeof window !== "undefined" ? window : globalThis);
