const test = require("node:test");
const assert = require("node:assert/strict");

function loadDetectorClient(configOverrides = {}) {
  globalThis.SG = {
    config: {
      API_BASE: "http://127.0.0.1:8000",
      BACKEND_AUTH_TOKEN: "",
      MIN_BLOCK_LEVEL: "medium",
      ...configOverrides,
    },
  };

  globalThis.FormData = class FormData {
    constructor() {
      this.entries = [];
    }

    append(key, value) {
      this.entries.push([key, value]);
    }

    has(key) {
      return this.entries.some(([entryKey]) => entryKey === key);
    }
  };

  delete require.cache[require.resolve("../src/services/detectorClient.js")];
  require("../src/services/detectorClient.js");
  return globalThis.SG.detectorClient;
}

test("detectText adds bearer auth when configured", async () => {
  let fetchOptions = null;
  globalThis.fetch = async (url, options) => {
    fetchOptions = { url, options };
    return {
      ok: true,
      async json() {
        return { risk_level: "low", detected_fields: [] };
      },
    };
  };

  const detectorClient = loadDetectorClient({
    BACKEND_AUTH_TOKEN: "extension-token",
  });

  await detectorClient.detectText("hello");

  assert.equal(fetchOptions.url, "http://127.0.0.1:8000/detect");
  assert.deepEqual(fetchOptions.options.headers, {
    Authorization: "Bearer extension-token",
  });
});

test("detectFile omits auth header when token is empty", async () => {
  let fetchOptions = null;
  globalThis.fetch = async (url, options) => {
    fetchOptions = { url, options };
    return {
      ok: true,
      async json() {
        return { risk_level: "low", detected_fields: [] };
      },
    };
  };

  const detectorClient = loadDetectorClient();
  const formData = new globalThis.FormData();

  await detectorClient.detectFile(formData);

  assert.deepEqual(fetchOptions.options.headers, {});
});
