import type { Rule } from "../types.js";
import { toolDescriptionRules } from "./tool-description.js";
import { configRules } from "./config.js";
import { sourceRules } from "./source.js";
import { skillRules } from "./skill.js";

export function allRules(): Rule[] {
  return [...toolDescriptionRules, ...configRules, ...sourceRules, ...skillRules];
}

export { toolDescriptionRules, configRules, sourceRules, skillRules };
