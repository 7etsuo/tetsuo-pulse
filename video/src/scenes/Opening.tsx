import React from "react";
import { useCurrentFrame, useVideoConfig, spring, interpolate, Easing } from "remotion";
import { Background } from "../components/Background";
import { AnimatedCounter } from "../components/AnimatedCounter";
import { FadeIn } from "../components/FadeIn";
import { Badge } from "../components/Badge";
import { colors } from "../lib/colors";
import { fontFamily } from "../lib/fonts";

export const Opening: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const logoScale = spring({
    frame,
    fps,
    config: { damping: 100, stiffness: 200 },
  });

  const titleOpacity = interpolate(frame, [20, 40], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  const statsOpacity = interpolate(frame, [60, 80], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  return (
    <Background>
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          gap: 32,
        }}
      >
        {/* Logo / Icon */}
        <div
          style={{
            transform: `scale(${logoScale})`,
            width: 120,
            height: 120,
            borderRadius: 28,
            background: `linear-gradient(135deg, ${colors.primary}, ${colors.purple})`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <svg width={64} height={64} viewBox="0 0 64 64">
            <path
              d="M16 48 L32 8 L48 48 M22 36 L42 36"
              stroke="white"
              strokeWidth={5}
              strokeLinecap="round"
              strokeLinejoin="round"
              fill="none"
            />
          </svg>
        </div>

        {/* Title */}
        <div style={{ opacity: titleOpacity, textAlign: "center" }}>
          <div
            style={{
              fontFamily: fontFamily.mono,
              fontSize: 72,
              fontWeight: 800,
              color: colors.text,
              letterSpacing: -2,
            }}
          >
            tetsuo-pulse
          </div>
          <div
            style={{
              fontFamily: fontFamily.sans,
              fontSize: 28,
              color: colors.muted,
              marginTop: 8,
            }}
          >
            High-Performance C Socket Library
          </div>
        </div>

        {/* Stats row */}
        <div
          style={{
            opacity: statsOpacity,
            display: "flex",
            alignItems: "center",
            gap: 40,
            marginTop: 16,
          }}
        >
          {[
            { to: 518, suffix: "K lines", delay: 70 },
            { to: 211, suffix: " tests", delay: 78 },
            { to: 165, suffix: " fuzz harnesses", delay: 86 },
            { to: 26, suffix: " RFCs", delay: 94 },
          ].map((stat, i) => (
            <div key={i} style={{ display: "flex", alignItems: "baseline", gap: 4 }}>
              <AnimatedCounter
                to={stat.to}
                delay={stat.delay}
                duration={50}
                fontSize={40}
                color={colors.primary}
              />
              <span
                style={{
                  fontFamily: fontFamily.sans,
                  fontSize: 18,
                  color: colors.muted,
                }}
              >
                {stat.suffix}
              </span>
            </div>
          ))}
        </div>

        {/* Tagline */}
        <FadeIn delay={140} duration={25}>
          <Badge
            label="The ONLY C library with native gRPC over HTTP/3"
            color={colors.success}
            delay={140}
            fontSize={20}
          />
        </FadeIn>
      </div>
    </Background>
  );
};
