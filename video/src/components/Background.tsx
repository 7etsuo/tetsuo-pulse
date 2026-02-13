import React from "react";
import { useCurrentFrame, interpolate } from "remotion";
import { colors } from "../lib/colors";

interface BackgroundProps {
  children: React.ReactNode;
}

export const Background: React.FC<BackgroundProps> = ({ children }) => {
  const frame = useCurrentFrame();

  const gradientAngle = interpolate(frame, [0, 10800], [0, 360], {
    extrapolateRight: "extend",
  });

  return (
    <div
      style={{
        width: 1920,
        height: 1080,
        backgroundColor: colors.bg,
        position: "relative",
        overflow: "hidden",
      }}
    >
      {/* Subtle radial glow */}
      <div
        style={{
          position: "absolute",
          inset: 0,
          background: `radial-gradient(ellipse 80% 60% at 50% 40%, ${colors.primary}08, transparent)`,
        }}
      />

      {/* Animated grid */}
      <svg
        width={1920}
        height={1080}
        style={{ position: "absolute", inset: 0, opacity: 0.04 }}
      >
        <defs>
          <pattern id="grid" width={60} height={60} patternUnits="userSpaceOnUse">
            <path
              d="M 60 0 L 0 0 0 60"
              fill="none"
              stroke={colors.text}
              strokeWidth={0.5}
            />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#grid)" />
      </svg>

      {/* Rotating gradient accent */}
      <div
        style={{
          position: "absolute",
          top: -200,
          right: -200,
          width: 600,
          height: 600,
          borderRadius: "50%",
          background: `conic-gradient(from ${gradientAngle}deg, ${colors.primary}06, ${colors.purple}04, transparent)`,
          filter: "blur(80px)",
        }}
      />

      {/* Content */}
      <div style={{ position: "relative", zIndex: 1, width: "100%", height: "100%" }}>
        {children}
      </div>
    </div>
  );
};
