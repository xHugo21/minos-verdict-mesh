(function initConfig(root) {
  const sg = (root.SG = root.SG || {});

  const API_BASE = "http://127.0.0.1:8000";
  const BACKEND_AUTH_TOKEN = "";

  sg.config = {
    API_BASE,
    BACKEND_AUTH_TOKEN,
    MIN_BLOCK_LEVEL: "medium",
  };
})(typeof window !== "undefined" ? window : globalThis);
