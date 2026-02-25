const test = require("node:test");
const assert = require("node:assert/strict");

function setup({ resultFactory }) {
  const listeners = new Map();
  const dispatched = [];
  let renderCall = null;
  let sendAnywayHandler = null;
  let sendSanitizedHandler = null;
  const composer = {
    tagName: "TEXTAREA",
    value: "",
    dispatchEvent: () => {},
  };
  const sendButton = { tagName: "BUTTON" };
  let sendCount = 0;

  globalThis.document = {
    addEventListener: (type, handler) => {
      listeners.set(type, handler);
    },
  };

  globalThis.Event = class Event {
    constructor(type, init = {}) {
      this.type = type;
      this.bubbles = Boolean(init.bubbles);
    }
  };

  globalThis.DataTransfer = class DataTransfer {
    constructor() {
      this._items = [];
      this.items = {
        add: (file) => {
          this._items.push(file);
          this.files = this._items.slice();
        },
      };
      this.files = [];
    }
  };

  globalThis.SG = {};
  delete require.cache[require.resolve("../src/state/alertStore.js")];
  require("../src/state/alertStore.js");

  globalThis.SG.panel = {
    render: (result, context, meta) => {
      renderCall = { result, context, meta };
    },
    onSendAnyway: (fn) => {
      sendAnywayHandler = fn;
    },
    onSendSanitized: (fn) => {
      sendSanitizedHandler = fn;
    },
    onDismiss: () => {},
    hide: () => {},
  };

  globalThis.SG.loadingState = {
    show: () => {},
    hide: () => {},
  };

  globalThis.SG.chatSelectors = {
    findComposer: () => composer,
    findSendButton: () => sendButton,
    setComposerText: (el, text) => {
      el.value = text;
    },
    triggerSend: () => {
      sendCount += 1;
    },
  };

  const analyzeCalls = [];
  const analyzeFilesCalls = [];
  globalThis.SG.fileAnalyzer = {
    analyzeFile: async (file) => {
      analyzeCalls.push(file);
      return resultFactory(file);
    },
    analyzeFiles: async (files) => {
      analyzeFilesCalls.push(files);
      // For multi-file analysis, combine results from all files
      // In tests we just return the result from first file for simplicity
      return resultFactory(files[0]);
    },
  };

  delete require.cache[require.resolve("../src/controllers/fileInterceptor.js")];
  require("../src/controllers/fileInterceptor.js");
  globalThis.SG.fileInterceptor.attach();

  const handler = listeners.get("change");

  function createInput(files) {
    return {
      type: "file",
      files,
      dataset: {},
      value: "original",
      dispatchEvent: (evt) => {
        dispatched.push(evt);
      },
    };
  }

  return {
    handler,
    createInput,
    analyzeCalls,
    analyzeFilesCalls,
    dispatched,
    get renderCall() {
      return renderCall;
    },
    get sendAnywayHandler() {
      return sendAnywayHandler;
    },
    get sendSanitizedHandler() {
      return sendSanitizedHandler;
    },
    get composer() {
      return composer;
    },
    get sendCount() {
      return sendCount;
    },
  };
}

test("warn auto-allows upload and shows dismiss-only panel", async () => {
  const env = setup({
    resultFactory: () => ({
      decision: "warn",
      risk_level: "low",
      detected_fields: [],
    }),
  });

  const input = env.createInput([{ name: "note.txt", size: 12 }]);
  let prevented = false;
  let stopped = false;

  await env.handler({
    target: input,
    preventDefault: () => {
      prevented = true;
    },
    stopImmediatePropagation: () => {
      stopped = true;
    },
  });

  assert.equal(prevented, true);
  assert.equal(stopped, true);
  assert.equal(env.analyzeFilesCalls.length, 1);
  assert.equal(env.dispatched.length, 1);
  assert.equal(input.dataset.sgBypass, "true");
  assert.equal(input.value, "original");
  assert.equal(env.renderCall.meta.mode, "warn");
  assert.equal(env.renderCall.meta.requireAction, false);
});

test("block gates upload until user action", async () => {
  const env = setup({
    resultFactory: () => ({
      decision: "block",
      risk_level: "high",
      detected_fields: [],
    }),
  });

  const input = env.createInput([{ name: "secret.txt", size: 42 }]);
  let prevented = false;
  let stopped = false;

  await env.handler({
    target: input,
    preventDefault: () => {
      prevented = true;
    },
    stopImmediatePropagation: () => {
      stopped = true;
    },
  });

  assert.equal(prevented, true);
  assert.equal(stopped, true);
  assert.equal(env.dispatched.length, 0);
  assert.equal(input.value, "");
  assert.equal(env.renderCall.meta.mode, "block");
  assert.equal(env.renderCall.meta.requireAction, true);
  assert.equal(env.renderCall.meta.primaryActionLabel, "Upload anyway");

  assert.equal(typeof env.sendAnywayHandler, "function");
  env.sendAnywayHandler();
  assert.equal(env.dispatched.length, 1);
  assert.equal(input.dataset.sgBypass, "true");
});

test("block with anonymized text sends sanitized message", async () => {
  const env = setup({
    resultFactory: () => ({
      decision: "block",
      risk_level: "high",
      detected_fields: [],
      anonymized_text: "REDACTED",
    }),
  });

  const input = env.createInput([{ name: "secret.txt", size: 42 }]);

  await env.handler({
    target: input,
    preventDefault: () => {},
    stopImmediatePropagation: () => {},
  });

  assert.equal(env.dispatched.length, 0);
  assert.equal(input.value, "");
  assert.equal(typeof env.sendSanitizedHandler, "function");

  env.sendSanitizedHandler();
  await new Promise((resolve) => setTimeout(resolve, 60));
  assert.equal(env.composer.value, "REDACTED");
  assert.equal(env.sendCount, 1);
  assert.equal(env.dispatched.length, 0);
});
