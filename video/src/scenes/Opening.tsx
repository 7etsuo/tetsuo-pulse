import React from "react";
import { useCurrentFrame, useVideoConfig, spring, interpolate, Img, staticFile } from "remotion";
import { Background } from "../components/Background";
import { AnimatedCounter } from "../components/AnimatedCounter";
import { FadeIn } from "../components/FadeIn";
import { Badge } from "../components/Badge";
import { colors } from "../lib/colors";
import { fontFamily } from "../lib/fonts";

export const Opening: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  // Logo springs in FAST — visible by frame 3-4
  const logoScale = spring({
    frame,
    fps,
    config: { damping: 80, stiffness: 300 },
  });

  // Title appears almost immediately
  const titleOpacity = interpolate(frame, [3, 12], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  // Stats visible quickly
  const statsOpacity = interpolate(frame, [12, 22], [0, 1], {
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
        {/* Logo */}
        <div
          style={{
            transform: `scale(${logoScale})`,
            width: 120,
            height: 120,
            borderRadius: 28,
            overflow: "hidden",
          }}
        >
          <Img
            src={staticFile("tetsuo.jpg")}
            style={{ width: 120, height: 120, objectFit: "cover" }}
          />
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
            { to: 518, suffix: "K lines", delay: 15 },
            { to: 211, suffix: " tests", delay: 20 },
            { to: 165, suffix: " fuzz harnesses", delay: 25 },
            { to: 26, suffix: " RFCs", delay: 30 },
          ].map((stat, i) => (
            <div key={i} style={{ display: "flex", alignItems: "baseline", gap: 4 }}>
              <AnimatedCounter
                to={stat.to}
                delay={stat.delay}
                duration={35}
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
        <FadeIn delay={50} duration={15}>
          <Badge
            label="The ONLY C library with native gRPC over HTTP/3"
            color={colors.success}
            delay={50}
            fontSize={20}
          />
        </FadeIn>
      </div>
    </Background>
  );
};
