import React from "react";
import { useCurrentFrame } from "remotion";
import { colors } from "../lib/colors";
import { fontFamily } from "../lib/fonts";
import { fadeIn } from "../lib/animate";

interface BadgeProps {
  label: string;
  color?: string;
  delay?: number;
  fontSize?: number;
}

export const Badge: React.FC<BadgeProps> = ({
  label,
  color = colors.primary,
  delay = 0,
  fontSize = 16,
}) => {
  const frame = useCurrentFrame();
  const opacity = fadeIn(frame, delay, 15);

  return (
    <span
      style={{
        opacity,
        display: "inline-flex",
        alignItems: "center",
        padding: "6px 16px",
        borderRadius: 999,
        backgroundColor: `${color}18`,
        border: `1px solid ${color}40`,
        fontFamily: fontFamily.sans,
        fontSize,
        fontWeight: 600,
        color,
      }}
    >
      {label}
    </span>
  );
};
