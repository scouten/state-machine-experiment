import { Context, mergeSettings, type Settings } from "@contentauth/c2pa-utilities";

export type ReaderContext = Pick<Context, "settings" | "toJson">;

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function validateReaderSettings(settings: unknown, hasOcspHost: boolean): asserts settings is Settings {
  if (!object(settings)) throw new Error("Invalid Context");
  for (const [section, value] of Object.entries(settings)) {
    if (!["trust", "cawgTrust", "verify"].includes(section) || !object(value))
      throw new Error(`Unsupported reader setting: ${section}`);
    for (const [key, field] of Object.entries(value)) {
      const anchorValue = (typeof field === "string" || Array.isArray(field)) &&
        (typeof field === "string" || field.every((entry) => typeof entry === "string"));
      const supported = ((section === "trust" || section === "cawgTrust") &&
        ["trustAnchors", "userAnchors"].includes(key) && anchorValue) ||
        (section === "verify" && key === "ocspFetch" && (field === false || (field === true && hasOcspHost))) ||
        (section === "verify" && key === "verifyTrust" && typeof field === "boolean") ||
        ((section === "trust" || section === "cawgTrust") && key === "verifyTrustList" &&
          typeof field === "boolean");
      if (!supported) throw new Error(`Unsupported reader setting: ${section}.${key}`);
    }
  }
}

export function readerDefaults(settings: unknown): Settings {
  const value = settings === undefined ? {} : settings;
  // Transport availability is per operation, not a loader-wide authorization.
  validateReaderSettings(value, true);
  return structuredClone(value);
}

export function factoryContext(defaults: Settings, settings: Settings | undefined): Context {
  if (settings !== undefined) validateReaderSettings(settings, true);
  return new Context(mergeSettings(defaults, settings ?? {}));
}

export function rejectBuilderDefaults(defaults: Settings): void {
  if (Object.keys(defaults).length)
    throw new Error("Builder factory settings inheritance is not supported; use Builder.fromDefinition without settings");
}

export async function contextJson(context?: ReaderContext, hasOcspHost = false): Promise<string | undefined> {
  if (!context) return undefined;
  validateReaderSettings(context.settings ?? {}, hasOcspHost);
  return await context.toJson();
}
