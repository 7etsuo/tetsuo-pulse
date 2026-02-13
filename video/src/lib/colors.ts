export const colors = {
  bg: "#0a0a0a",
  bgCard: "#141414",
  primary: "#3b82f6",
  success: "#10b981",
  danger: "#ef4444",
  text: "#ffffff",
  muted: "#9ca3af",
  border: "#1e293b",
  purple: "#8b5cf6",
} as const;

export type ColorToken = keyof typeof colors;
