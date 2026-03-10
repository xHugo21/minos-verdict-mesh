/**
 * Extension Settings
 *
 * Stores user-configurable settings in chrome.storage and keeps a local cache
 * for fast synchronous reads inside content scripts.
 */
(function initSettings(root) {
  const sg = (root.SG = root.SG || {});

  const DEFAULTS = {
    detectionEnabled: true,
  };

  const state = {
    detectionEnabled: DEFAULTS.detectionEnabled,
    loaded: false,
  };

  const subscribers = new Set();
  let readyResolve = null;

  const readyPromise = new Promise((resolve) => {
    readyResolve = resolve;
  });

  function setLoaded() {
    if (state.loaded) return;
    state.loaded = true;
    if (readyResolve) {
      readyResolve();
      readyResolve = null;
    }
  }

  function getState() {
    return {
      detectionEnabled: state.detectionEnabled,
      loaded: state.loaded,
    };
  }

  function notify() {
    const snapshot = getState();
    subscribers.forEach((handler) => {
      try {
        handler(snapshot);
      } catch (err) {
        console.warn(
          "[MinosVerdictExtension] Settings subscriber error:",
          err,
        );
      }
    });
  }

  function isDetectionEnabled() {
    return !!state.detectionEnabled;
  }

  function setDetectionEnabled(enabled) {
    const next = !!enabled;
    state.detectionEnabled = next;
    setLoaded();
    notify();

    if (root.chrome?.storage?.local) {
      root.chrome.storage.local.set({ detectionEnabled: next });
    }
  }

  function subscribe(handler) {
    if (typeof handler !== "function") return () => {};
    subscribers.add(handler);
    return () => subscribers.delete(handler);
  }

  function load() {
    if (!root.chrome?.storage?.local) {
      setLoaded();
      notify();
      return;
    }

    root.chrome.storage.local.get(DEFAULTS, (items) => {
      if (root.chrome.runtime?.lastError) {
        console.warn(
          "[MinosVerdictExtension] Failed to load settings:",
          root.chrome.runtime.lastError,
        );
      }
      if (state.loaded) {
        return;
      }
      state.detectionEnabled =
        typeof items.detectionEnabled === "boolean"
          ? items.detectionEnabled
          : DEFAULTS.detectionEnabled;
      setLoaded();
      notify();
    });
  }

  if (root.chrome?.storage?.onChanged) {
    root.chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== "local") return;
      if (changes.detectionEnabled) {
        state.detectionEnabled = !!changes.detectionEnabled.newValue;
        setLoaded();
        notify();
      }
    });
  }

  load();

  sg.settings = {
    getState,
    isDetectionEnabled,
    setDetectionEnabled,
    subscribe,
    whenReady: () => readyPromise,
  };
})(typeof window !== "undefined" ? window : globalThis);
