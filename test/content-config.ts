import {
  COLLECTION_SETTINGS,
  CONTENT_COLLECTION_CATEGORIES,
  loadConfig,
  type ObserverConfig,
} from "../src/config.js";

/**
 * Loads a configuration for a computer whose owner consented to full
 * activity, with every content category off unless `environment` turns it
 * on. Tests use it to enable exactly the categories they exercise.
 */
export function loadContentConfig(
  environment: NodeJS.ProcessEnv,
): ObserverConfig {
  return loadConfig({
    PHIGON_OBSERVABILITY_PROFILE: "full",
    ...Object.fromEntries(
      CONTENT_COLLECTION_CATEGORIES.map((category) => [
        COLLECTION_SETTINGS[category],
        "false",
      ]),
    ),
    ...environment,
  });
}
