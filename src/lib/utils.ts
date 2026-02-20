import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatRiskColor(score: number) {
  if (score < 30) return "text-emerald-500";
  if (score < 70) return "text-amber-500";
  return "text-rose-500";
}

export function formatRiskBg(score: number) {
  if (score < 30) return "bg-emerald-500/10 border-emerald-500/20";
  if (score < 70) return "bg-amber-500/10 border-amber-500/20";
  return "bg-rose-500/10 border-rose-500/20";
}
