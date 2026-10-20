/** Offline trust material, supplied explicitly rather than downloaded. */
export interface AdobeTrustSettings {
  trustAnchors: string | string[];
  userAnchors?: string | string[];
  verifyTrustList?: boolean;
}

/** Explicit read policy. Online trust-list discovery is not implicit. */
export interface AdobeReadConfig {
  trust: false | { trust: AdobeTrustSettings; cawgTrust?: AdobeTrustSettings };
}

export function validateConfig(config: AdobeReadConfig, loader = false): void {
  if (!config || (config.trust !== false &&
    (typeof config.trust !== "object" || config.trust === null || !("trust" in config.trust))))
    throw new Error("Reading requires explicit trust: false or supplied trust anchors; trust-list loading is not implemented");
  const supported = loader ? ["trust", "wasmSrc", "workerSrc"] : ["trust"];
  for (const key of Object.keys(config)) {
    if (!supported.includes(key)) throw new Error(`Unsupported Adobe reader configuration: ${key}`);
  }
  if (config.trust !== false) {
    for (const key of Object.keys(config.trust)) {
      if (!["trust", "cawgTrust"].includes(key)) throw new Error(`Unsupported Adobe trust configuration: ${key}`);
    }
    for (const section of Object.values(config.trust)) {
      if (typeof section !== "object" || section === null)
        throw new Error("Trust settings must supply PEM trustAnchors");
      for (const [key, value] of Object.entries(section)) {
        if (key === "verifyTrustList" && typeof value === "boolean") continue;
        if (["trustAnchors", "userAnchors"].includes(key) &&
          (typeof value === "string" || (Array.isArray(value) && value.every((entry) => typeof entry === "string"))) &&
          (typeof value === "string" ? [value] : value).every((entry) =>
            entry.includes("-----BEGIN CERTIFICATE-----") && !/^https?:/i.test(entry))) continue;
        throw new Error(`Unsupported Adobe trust setting: ${key}`);
      }
      if (!("trustAnchors" in section)) throw new Error("Trust settings must supply PEM trustAnchors");
    }
  }
}

export function readerSettings(config: AdobeReadConfig) {
  const inline = (value: AdobeTrustSettings) => ({
    trustAnchors: Array.isArray(value.trustAnchors) ? value.trustAnchors.join("\n") : value.trustAnchors,
    ...(value.userAnchors !== undefined ? {
      userAnchors: Array.isArray(value.userAnchors) ? value.userAnchors.join("\n") : value.userAnchors,
    } : {}),
    ...(value.verifyTrustList !== undefined ? { verifyTrustList: value.verifyTrustList } : {}),
  });
  return {
    verify: { verifyTrust: config.trust !== false, ocspFetch: false },
    ...(config.trust === false
      ? { cawgTrust: { verifyTrustList: false } }
      : {
        trust: inline(config.trust.trust),
        ...(config.trust.cawgTrust ? { cawgTrust: inline(config.trust.cawgTrust) } : {}),
      }),
  };
}
