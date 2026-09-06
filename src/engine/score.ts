import type { Finding, Severity } from "../types.js";

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 40,
  high: 25,
  medium: 15,
  low: 5,
  info: 0,
};

export function scoreFindings(findings: Finding[]): number {
  const raw = findings.reduce((sum, f) => sum + SEVERITY_WEIGHTS[f.severity], 0);
  return Math.min(100, raw);
}

export type Grade = "A" | "B" | "C" | "D" | "F";

export function gradeScore(findings: Finding[], score: number): Grade {
  if (findings.some((f) => f.severity === "critical")) return "F";
  if (findings.length === 0 || findings.every((f) => f.severity === "info")) return "A";
  if (score < 20) return "B";
  if (score < 40) return "C";
  if (score < 60) return "D";
  return "F";
}

const GRADE_ORDER: Grade[] = ["A", "B", "C", "D", "F"];

export function worstGrade(grades: Grade[]): Grade {
  let worst: Grade = "A";
  for (const g of grades) {
    if (GRADE_ORDER.indexOf(g) > GRADE_ORDER.indexOf(worst)) worst = g;
  }
  return worst;
}
