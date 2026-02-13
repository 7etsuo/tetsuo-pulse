import React from "react";
import { useCurrentFrame } from "remotion";
import { colors } from "../lib/colors";
import { fontFamily } from "../lib/fonts";
import { fadeIn, slideIn } from "../lib/animate";
import { AnimatedCounter } from "./AnimatedCounter";

interface StatCardProps {
  value: number;
  label: string;
  suffix?: string;
  prefix?: string;
  delay?: number;
  color?: string;
  width?: number;
}

export const StatCard: React.FC<StatCardProps> = ({
  value,
  label,
  suffix = "",
  prefix = "",
  delay = 0,
  color = colors.primary,
  width = 280,
}) => {
  const frame = useCurrentFrame();
  const opacity = fadeIn(frame, delay, 20);
  const translateY = slideIn(frame, "up", delay, 20, 20);

  return (
    <div
      style={{
        opacity,
        transform: `translateY(${translateY}px)`,
        width,
        padding: "28px 24px",
        backgroundColor: colors.bgCard,
        borderRadius: 16,
        border: `1px solid ${colors.border}`,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 8,
      }}
    >
      <AnimatedCounter
        to={value}
        delay={delay + 10}
        duration={45}
        suffix={suffix}
        prefix={prefix}
        fontSize={48}
        color={color}
      />
      <span
        style={{
          fontFamily: fontFamily.sans,
          fontSize: 18,
          color: colors.muted,
          textTransform: "uppercase",
          letterSpacing: 2,
        }}
      >
        {label}
      </span>
    </div>
  );
};
