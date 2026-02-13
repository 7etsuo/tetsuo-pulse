import React from "react";
import { useCurrentFrame, spring, useVideoConfig, interpolate, Easing } from "remotion";
import { Background } from "../components/Background";
import { FadeIn } from "../components/FadeIn";
import { Badge } from "../components/Badge";
import { colors } from "../lib/colors";
import { fontFamily } from "../lib/fonts";
import { fadeIn } from "../lib/animate";

export const Closing: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const taglineScale = spring({
    frame: Math.max(0, frame - 10),
    fps,
    config: { damping: 100, stiffness: 180 },
  });

  const fadeOutStart = 240;
  const finalOpacity = interpolate(frame, [fadeOutStart, fadeOutStart + 60], [1, 0], {
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
          gap: 40,
          opacity: finalOpacity,
        }}
      >
        {/* Main tagline */}
        <div
          style={{
            transform: `scale(${taglineScale})`,
            textAlign: "center",
          }}
        >
          <div
            style={{
              fontFamily: fontFamily.sans,
              fontSize: 56,
              fontWeight: 800,
              color: colors.text,
              lineHeight: 1.2,
            }}
          >
            From TCP to gRPC.
          </div>
          <div
            style={{
              fontFamily: fontFamily.sans,
              fontSize: 56,
              fontWeight: 800,
              color: colors.primary,
              lineHeight: 1.2,
            }}
          >
            One library. Pure C.
          </div>
        </div>

        {/* GitHub URL */}
        <FadeIn delay={60}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 16,
              padding: "16px 32px",
              borderRadius: 16,
              backgroundColor: colors.bgCard,
              border: `1px solid ${colors.border}`,
            }}
          >
            {/* GitHub icon */}
            <svg width={32} height={32} viewBox="0 0 24 24" fill={colors.text}>
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
            </svg>
            <span
              style={{
                fontFamily: fontFamily.mono,
                fontSize: 24,
                color: colors.text,
              }}
            >
              github.com/7etsuo/tetsuo-pulse
            </span>
          </div>
        </FadeIn>

        {/* Badges */}
        <FadeIn delay={100}>
          <div style={{ display: "flex", gap: 16 }}>
            <Badge label="MIT License" color={colors.success} delay={100} fontSize={18} />
            <Badge label="C11" color={colors.primary} delay={110} fontSize={18} />
            <Badge label="POSIX" color={colors.purple} delay={120} fontSize={18} />
          </div>
        </FadeIn>

        {/* Sub tagline */}
        <FadeIn delay={140}>
          <div
            style={{
              fontFamily: fontFamily.sans,
              fontSize: 22,
              color: colors.muted,
              textAlign: "center",
            }}
          >
            518K lines of battle-tested C. Start building today.
          </div>
        </FadeIn>
      </div>
    </Background>
  );
};
