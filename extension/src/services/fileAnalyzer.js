(function initFileAnalyzer(root) {
  const sg = (root.SG = root.SG || {});

  /**
   * Analyze files Supports both single file and multiple files.
   *
   * @param {File[]} files - Array of File objects to analyze
   * @returns {Promise} Detection result covering all files
   */
  async function analyzeFiles(files) {
    if (!files || !Array.isArray(files) || files.length === 0) {
      throw new Error("No files provided");
    }

    const fileNames = files.map((f) => f.name).join(", ");
    const totalSize = files.reduce((sum, f) => sum + f.size, 0);

    console.log(
      `[SensitiveDataDetectorExtension] Analyzing ${files.length} files: ${fileNames} (${totalSize} bytes total)`,
    );

    const formData = new FormData();

    files.forEach((file) => {
      formData.append("files", file);
    });

    try {
      const result = await sg.detectorClient.detectFile(formData);

      // Backend may return error for unsupported/invalid files
      if (result.error) {
        console.warn(
          `[SensitiveDataDetectorExtension] Backend validation error: ${result.error}`,
        );
      }

      result.fileInfo = {
        count: files.length,
        names: files.map((f) => f.name),
        totalSize: totalSize,
      };

      console.log(
        `[SensitiveDataDetectorExtension] Analysis complete for ${files.length} files:`,
        {
          riskLevel: result.risk_level,
          fieldsDetected: result.detected_fields?.length || 0,
          hasExtractedText: !!result.extracted_snippet,
          error: result.error,
        },
      );

      return result;
    } catch (error) {
      console.error(
        `[SensitiveDataDetectorExtension] Error analyzing ${files.length} files:`,
        error,
      );
      throw error;
    }
  }

  sg.fileAnalyzer = {
    analyzeFiles,
  };
})(typeof window !== "undefined" ? window : globalThis);
