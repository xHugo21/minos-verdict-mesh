(function initMain(root) {
  const sg = (root.SG = root.SG || {});

  /**
   * Bootstrap the extension with platform detection
   */
  async function bootstrap() {
    if (sg.settings?.whenReady) {
      await sg.settings.whenReady();
    }

    // Detect and activate the appropriate platform
    const platform = await sg.platformRegistry.detectAndActivate();

    if (!platform) {
      console.warn(
        "[MinosVerdictMesh] No supported platform detected on this page",
      );
      return;
    }

    console.log(
      `[MinosVerdictMesh] Successfully initialized on ${platform.displayName}`,
    );

    // Initialize UI components
    sg.panel.ensure();
    sg.highlights.ensureHighlightCSS();

    // Attach controllers
    sg.sendInterceptor.attach();
    sg.fileInterceptor.attach();
  }

  function startWithDelay() {
    setTimeout(bootstrap, 800);
  }

  if (
    document.readyState === "complete" ||
    document.readyState === "interactive"
  ) {
    startWithDelay();
  } else {
    window.addEventListener("load", startWithDelay);
  }
})(typeof window !== "undefined" ? window : globalThis);
