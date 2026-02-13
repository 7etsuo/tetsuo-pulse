import React from "react";
import { useCurrentFrame, interpolate, Easing } from "remotion";
import { fontFamily } from "../lib/fonts";
import { colors } from "../lib/colors";

interface AnimatedCounterProps {
  from?: number;
  to: number;
  duration?: number;
  delay?: number;
  suffix?: string;
  prefix?: string;
  fontSize?: number;
  color?: string;
  decimals?: number;
}

export const AnimatedCounter: React.FC<AnimatedCounterProps> = ({
  from = 0,
  to,
  duration = 60,
  delay = 0,
  suffix = "",
  prefix = "",
  fontSize = 64,
  color = colors.text,
  decimals = 0,
}) => {
  const frame = useCurrentFrame();

  const value = interpolate(frame, [delay, delay + duration], [from, to], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.out(Easing.cubic),
  });

  const formatted =
    decimals > 0
      ? value.toFixed(decimals)
      : Math.round(value).toLocaleString();

  return (
    <span
      style={{
        fontFamily: fontFamily.mono,
        fontSize,
        fontWeight: 700,
        color,
        fontVariantNumeric: "tabular-nums",
      }}
    >
      {prefix}
      {formatted}
      {suffix}
    </span>
  );
};
