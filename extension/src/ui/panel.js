(function initPanel(root) {
  const sg = (root.SG = root.SG || {});

  const sendListeners = new Set();
  const sendSanitizedListeners = new Set();
  const dismissListeners = new Set();

  function ensurePanel() {
    let panel = document.getElementById("sg-llm-panel");
    if (panel) {
      mountPanel(panel);
      return panel;
    }

    panel = document.createElement("div");
    Object.assign(panel.style, {
      position: "relative",
      zIndex: 10,
      width: "100%",
      maxWidth: "760px",
      background: "rgba(32,33,35,0.97)",
      color: "#ECECF1",
      borderRadius: "18px",
      boxShadow: "0 12px 35px rgba(0,0,0,0.35)",
      padding: "20px 22px 24px",
      fontFamily:
        '"Sohne", "GT Walsheim", "Helvetica Neue", system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
      fontSize: "16px",
      lineHeight: "1.55",
      border: "1px solid rgba(255,255,255,0.08)",
      borderLeft: "4px solid #c5c5d2",
      boxSizing: "border-box",
      backdropFilter: "blur(6px)",
      maxHeight: "40vh",
      overflow: "hidden",
      display: "flex",
      flexDirection: "column",
    });
    panel.id = "sg-llm-panel";
    panel.style.display = "none";

    const titleRow = document.createElement("div");
    Object.assign(titleRow.style, {
      display: "flex",
      justifyContent: "space-between",
      alignItems: "center",
    });

    const title = document.createElement("div");
    title.id = "sg-llm-title";
    Object.assign(title.style, {
      fontWeight: "700",
      fontSize: "20px",
      marginBottom: "4px",
      letterSpacing: "-0.01em",
    });
    title.textContent = "⚠️ Risk Detected";
    titleRow.appendChild(title);

    panel.appendChild(titleRow);

    const content = document.createElement("div");
    Object.assign(content.style, {
      flex: "1",
      overflowY: "auto",
      overflowX: "hidden",
      paddingRight: "4px",
      paddingBottom: "12px",
      display: "flex",
      flexDirection: "column",
    });
    panel.appendChild(content);

    const policy = document.createElement("div");
    policy.id = "sg-llm-policy";
    Object.assign(policy.style, {
      opacity: "0.9",
      fontSize: "14px",
      margin: "6px 0",
      color: "#C5C5D2",
      textAlign: "left",
    });
    content.appendChild(policy);

    const metrics = document.createElement("div");
    metrics.id = "sg-llm-metrics";
    Object.assign(metrics.style, {
      opacity: "0.9",
      fontSize: "13px",
      margin: "0 0 12px",
      color: "#AEB0C3",
    });
    content.appendChild(metrics);

    const list = document.createElement("div");
    list.id = "sg-llm-list";
    Object.assign(list.style, {
      fontSize: "15px",
      overflow: "visible",
      paddingBottom: "8px",
    });
    content.appendChild(list);

    const actions = document.createElement("div");
    Object.assign(actions.style, {
      display: "flex",
      gap: "10px",
      marginTop: "16px",
      flexWrap: "wrap",
      position: "sticky",
      bottom: "0",
      background:
        "linear-gradient(180deg, rgba(32,33,35,0.97) 0%, rgba(32,33,35,0.97) 75%, rgba(32,33,35,0.92) 100%)",
      paddingTop: "10px",
    });

    const btnSendSanitized = document.createElement("button");
    btnSendSanitized.id = "sg-llm-send-sanitized";
    btnSendSanitized.textContent = "Send sanitized";
    btnSendSanitized.dataset.sgPanelButton = "true";
    Object.assign(btnSendSanitized.style, {
      flex: 1,
      border: "none",
      borderRadius: "12px",
      padding: "10px 16px",
      background: "linear-gradient(120deg,#0ba360,#3cba92)",
      color: "#0b1119",
      cursor: "pointer",
      fontSize: "15px",
      fontWeight: "700",
      boxShadow: "0 6px 18px rgba(60,186,146,0.35)",
      display: "none",
    });

    const btnSendAnyway = document.createElement("button");
    btnSendAnyway.id = "sg-llm-override";
    btnSendAnyway.textContent = "Send anyway";
    btnSendAnyway.dataset.sgPanelButton = "true";
    Object.assign(btnSendAnyway.style, {
      flex: 1,
      border: "none",
      borderRadius: "12px",
      padding: "10px 16px",
      background: "linear-gradient(120deg,#fa5555,#f23f5d)",
      color: "#fff",
      cursor: "pointer",
      fontSize: "15px",
      fontWeight: "600",
      boxShadow: "0 6px 18px rgba(242,63,93,0.35)",
    });

    const btnDismiss = document.createElement("button");
    btnDismiss.textContent = "Dismiss";
    btnDismiss.dataset.sgPanelButton = "true";
    Object.assign(btnDismiss.style, {
      flex: 0,
      borderRadius: "12px",
      padding: "10px 16px",
      background: "transparent",
      color: "#ECECF1",
      cursor: "pointer",
      fontSize: "15px",
      fontWeight: "600",
      border: "1px solid rgba(255,255,255,0.12)",
    });

    actions.appendChild(btnSendSanitized);
    actions.appendChild(btnSendAnyway);
    actions.appendChild(btnDismiss);
    panel.appendChild(actions);

    btnDismiss.addEventListener("click", () => {
      hidePanel();
      dismissListeners.forEach((fn) => fn());
    });
    btnSendAnyway.addEventListener("click", () => {
      sendListeners.forEach((fn) => fn());
    });
    btnSendSanitized.addEventListener("click", () => {
      sendSanitizedListeners.forEach((fn) => fn());
    });

    mountPanel(panel);

    panel._els = {
      title,
      list,
      policy,
      metrics,
      actions,
      btnSendSanitized,
      btnSendAnyway,
      btnDismiss,
    };
    return panel;
  }

  function applyInlinePanelStyles(panel) {
    Object.assign(panel.style, {
      position: "relative",
      margin: "0 auto",
      width: "100%",
      maxWidth: "760px",
      left: "unset",
      right: "unset",
      top: "unset",
      bottom: "unset",
    });
  }

  function mountPanel(panel) {
    const fallbackParent = document.body || document.documentElement;
    let host = null;
    let referenceNode = null;

    // Use platform-specific insertion point if available
    const platform = sg.platformRegistry?.getActive?.();
    if (platform && typeof platform.findPanelInsertionPoint === "function") {
      const insertionPoint = platform.findPanelInsertionPoint();

      if (insertionPoint && insertionPoint.host) {
        host = insertionPoint.host;
        referenceNode = insertionPoint.referenceNode || null;
      }
    }

    // Fallback to composer-based insertion
    if (!host) {
      const composer = sg.chatSelectors?.findComposer?.();
      const form = composer?.closest?.("form");
      host = form?.parentElement || composer?.parentElement || fallbackParent;
      referenceNode = form || composer || null;
    }

    // Check if we need to move the anchor
    let anchor = document.getElementById("sg-llm-panel-anchor");
    if (anchor && anchor.parentElement && anchor.parentElement !== host) {
      anchor.parentElement.removeChild(anchor);
      anchor = null;
    } else if (anchor && !anchor.parentElement) {
      anchor = null;
    }

    if (!anchor) {
      anchor = document.createElement("div");
      anchor.id = "sg-llm-panel-anchor";
      Object.assign(anchor.style, {
        width: "100%",
        display: "flex",
        justifyContent: "center",
        marginBottom: "16px",
        marginTop: "4px",
        padding: "0 8px",
        boxSizing: "border-box",
      });
      if (referenceNode && referenceNode.parentElement === host) {
        host.insertBefore(anchor, referenceNode);
      } else {
        host.appendChild(anchor);
      }
    }

    if (panel.parentElement !== anchor) {
      anchor.appendChild(panel);
    }
    applyInlinePanelStyles(panel);
  }

  function renderPanel(result, contextText = "", meta = {}) {
    const panel = ensurePanel();
    mountPanel(panel);
    const {
      title,
      list,
      policy,
      metrics,
      btnSendAnyway,
      btnSendSanitized,
      btnDismiss,
      actions,
    } = panel._els;
    list.innerHTML = "";

    const mode = meta.mode || "block";
    const {
      risk_level = "unknown",
      detected_fields = [],
      error = "",
    } = result || {};

    let titleText;
    if (error) {
      titleText = "⚠️ Analysis Error";
    } else {
      const riskLabel =
        risk_level === "high"
          ? "High"
          : risk_level === "medium"
            ? "Medium"
            : risk_level === "low"
              ? "Low"
              : "Unknown";
      titleText = `⚠️ ${riskLabel} Risk Detected`;
    }

    title.textContent = titleText;

    const baseText = contextText || "";

    // Display error message if present (takes precedence over remediation)
    const remediation = result?.remediation || "";

    if (error) {
      policy.innerHTML = `<div style="color: #ffa8a8; font-weight: 500;">${error}</div>`;
    } else if (remediation) {
      policy.innerHTML = `<div>${remediation}</div>`;
    } else {
      policy.innerHTML = "";
    }

    // Show timing if provided
    const durationMs = meta?.durationMs;
    if (typeof durationMs === "number" && isFinite(durationMs)) {
      const formatted =
        durationMs >= 1000
          ? `${(durationMs / 1000).toFixed(1)}s`
          : `${Math.round(durationMs)}ms`;
      metrics.textContent = `Analysis completed in ${formatted}`;
      metrics.style.textAlign = "left";
      metrics.style.display = "block";
    } else {
      metrics.textContent = "";
      metrics.style.display = "none";
    }

    const accentRisk =
      risk_level === "high"
        ? "#fa5a5a"
        : risk_level === "medium"
          ? "#ffd369"
          : risk_level === "low"
            ? "#10a37f"
            : "#c5c5d2";
    panel.style.borderLeft = `4px solid ${accentRisk}`;

    if (detected_fields.length) {
      const groups = new Map();
      for (const detected of detected_fields) {
        const fieldName = detected.field || "UNKNOWN";
        const value = (detected.value || "").trim();
        if (!value) continue;

        const pos = baseText
          ? baseText.indexOf(value)
          : Number.POSITIVE_INFINITY;
        const key = fieldName;
        let group = groups.get(key);
        if (!group) {
          group = {
            field: fieldName,
            sources: [],
            risk: sg.riskUtils.classifyField(detected),
            _seen: new Map(),
            minIdx: Number.POSITIVE_INFINITY,
          };
          groups.set(key, group);
        }

        const sources = Array.isArray(detected.sources) ? detected.sources : [];
        for (const source of sources) {
          if (!source || group.sources.includes(source)) continue;
          group.sources.push(source);
        }

        const prev = group._seen.get(value);
        const minPos = pos === -1 ? Number.POSITIVE_INFINITY : pos;
        if (prev === undefined || minPos < prev) {
          group._seen.set(value, minPos);
        }
      }

      for (const group of groups.values()) {
        group.items = Array.from(group._seen.entries())
          .map(([value, pos]) => ({ value, pos }))
          .sort((a, b) => a.pos - b.pos);
        group.minIdx = group.items.length
          ? group.items[0].pos
          : Number.POSITIVE_INFINITY;
        delete group._seen;
      }

      const ordered = Array.from(groups.values()).sort(
        sg.riskUtils.compareFieldGroups,
      );

      for (const group of ordered) {
        const item = document.createElement("div");
        item.style.margin = "10px 0";
        item.style.padding = "10px 12px";
        item.style.borderRadius = "12px";
        item.style.background = "rgba(255,255,255,0.02)";

        const head = document.createElement("div");
        head.style.display = "flex";
        head.style.justifyContent = "space-between";
        head.style.alignItems = "center";
        head.style.fontWeight = "600";
        head.style.fontSize = "15px";
        const accent =
          group.risk === "high"
            ? "#ff8c8c"
            : group.risk === "medium"
              ? "#ffd666"
              : "#7de6a3";

        const fieldName = document.createElement("span");
        fieldName.style.color = accent;
        fieldName.textContent = group.field;

        const sourceLabel = document.createElement("span");
        sourceLabel.style.color = "#9fa0b3";
        sourceLabel.style.fontWeight = "400";
        sourceLabel.style.fontSize = "13px";
        sourceLabel.style.marginLeft = "8px";
        const sourceText = group.sources.length
          ? group.sources.join(", ")
          : "Unknown";
        sourceLabel.textContent = `Sources: ${sourceText}`;

        head.appendChild(fieldName);
        head.appendChild(sourceLabel);

        const body = document.createElement("div");
        body.style.opacity = "0.9";
        body.style.fontSize = "14px";
        body.style.marginTop = "4px";
        body.style.color = "#ECECF1";
        body.style.textAlign = "left";
        const valuesOrdered = group.items.map((it) => it.value);
        body.textContent =
          valuesOrdered.slice(0, 4).join(", ") +
          (valuesOrdered.length > 4 ? "…" : "");

        item.appendChild(head);
        item.appendChild(body);
        list.appendChild(item);
      }
    } else {
      const empty = document.createElement("div");
      empty.textContent = "No sensitive fields detected.";
      empty.style.padding = "12px";
      empty.style.borderRadius = "10px";
      empty.style.background = "rgba(255,255,255,0.02)";
      empty.style.color = "#9fa0b3";
      list.appendChild(empty);
    }

    const hasSanitizedText =
      typeof result?.anonymized_text === "string" &&
      result.anonymized_text.trim().length > 0;
    const showActions = mode !== "warn" || meta?.requireAction === true;
    const showSanitized = hasSanitizedText && !meta?.hideSanitized;
    const primaryLabel = meta?.primaryActionLabel || "Send anyway";
    const secondaryLabel = meta?.secondaryActionLabel || "Send sanitized";
    if (btnSendAnyway) btnSendAnyway.textContent = primaryLabel;
    if (btnSendSanitized) btnSendSanitized.textContent = secondaryLabel;

    if (actions && btnDismiss && btnSendAnyway) {
      if (!showActions) {
        // Warn mode: hide action buttons, show only dismiss at full width
        btnSendSanitized.style.display = "none";
        btnSendAnyway.style.display = "none";
        btnDismiss.style.display = "inline-block";
        btnDismiss.style.flex = "1";
        actions.style.justifyContent = "flex-start";
        actions.style.gap = "10px";
      } else {
        // Block mode or gated warn: show action buttons
        if (!actions.contains(btnSendAnyway))
          actions.insertBefore(btnSendAnyway, btnDismiss);
        if (!actions.contains(btnSendSanitized))
          actions.insertBefore(btnSendSanitized, btnSendAnyway);
        btnSendSanitized.style.display = showSanitized
          ? "inline-block"
          : "none";
        btnSendAnyway.style.display = "inline-block";
        btnDismiss.style.display = "inline-block";
        btnSendSanitized.style.flex = "1";
        btnSendAnyway.style.flex = "1";
        btnDismiss.style.flex = "0";
        actions.style.justifyContent = "flex-start";
        actions.style.gap = "10px";
      }
    }

    panel.style.display = "flex";
  }

  function hidePanel() {
    const panel = document.getElementById("sg-llm-panel");
    if (panel) panel.style.display = "none";
  }

  function onSendAnyway(callback) {
    if (typeof callback === "function") sendListeners.add(callback);
  }

  function onSendSanitized(callback) {
    if (typeof callback === "function") sendSanitizedListeners.add(callback);
  }

  function onDismiss(callback) {
    if (typeof callback === "function") dismissListeners.add(callback);
  }

  sg.panel = {
    ensure: ensurePanel,
    render: renderPanel,
    hide: hidePanel,
    onSendAnyway,
    onSendSanitized,
    onDismiss,
  };
})(typeof window !== "undefined" ? window : globalThis);
