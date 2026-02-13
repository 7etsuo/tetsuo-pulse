import React from "react";
import { useCurrentFrame } from "remotion";
import { Background } from "../components/Background";
import { FadeIn } from "../components/FadeIn";
import { StatCard } from "../components/StatCard";
import { Badge } from "../components/Badge";
import { FeatureList } from "../components/FeatureList";
import { colors } from "../lib/colors";
import { fontFamily } from "../lib/fonts";
import { fadeIn, stagger } from "../lib/animate";

const SANITIZERS = [
  { label: "AddressSanitizer", abbr: "ASan", color: colors.danger },
  { label: "UndefinedBehavior", abbr: "UBSan", color: "#f59e0b" },
  { label: "ThreadSanitizer", abbr: "TSan", color: colors.purple },
];

const CONFORMANCE = [
  { text: "gRPC unary calls", available: true },
  { text: "gRPC server streaming", available: true },
  { text: "gRPC client streaming", available: true },
  { text: "gRPC bidirectional streaming", available: true },
  { text: "HTTP/2 interop (h2spec)", available: true },
  { text: "QUIC v1 (RFC 9000)", available: true },
  { text: "QPACK (RFC 9204 vectors)", available: true },
  { text: "HTTP/3 (RFC 9114)", available: true },
];

export const Quality: React.FC = () => {
  const frame = useCurrentFrame();

  return (
    <Background>
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          padding: "60px 100px",
          gap: 40,
          height: "100%",
        }}
      >
        {/* Title */}
        <FadeIn delay={5}>
          <div
            style={{
              fontFamily: fontFamily.sans,
              fontSize: 44,
              fontWeight: 700,
              color: colors.text,
            }}
          >
            Quality Infrastructure
          </div>
        </FadeIn>

        <div style={{ display: "flex", gap: 60, flex: 1 }}>
          {/* Left: stats + sanitizers */}
          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 32 }}>
            {/* Stat cards */}
            <div style={{ display: "flex", gap: 20 }}>
              <StatCard
                value={211}
                label="Tests"
                delay={15}
                color={colors.primary}
                width={220}
              />
              <StatCard
                value={165}
                label="Fuzz Harnesses"
                delay={25}
                color={colors.success}
                width={220}
              />
              <StatCard
                value={26}
                label="RFCs"
                delay={35}
                color={colors.purple}
                width={220}
              />
            </div>

            {/* Sanitizers */}
            <FadeIn delay={60}>
              <div
                style={{
                  fontFamily: fontFamily.sans,
                  fontSize: 20,
                  color: colors.muted,
                  marginBottom: 8,
                }}
              >
                Every PR runs with sanitizers:
              </div>
              <div style={{ display: "flex", gap: 12 }}>
                {SANITIZERS.map((san, i) => {
                  const d = stagger(i, 70, 10);
                  const opacity = fadeIn(frame, d, 12);
                  return (
                    <div
                      key={i}
                      style={{
                        opacity,
                        padding: "16px 24px",
                        borderRadius: 12,
                        backgroundColor: `${san.color}10`,
                        border: `1px solid ${san.color}30`,
                        display: "flex",
                        flexDirection: "column",
                        alignItems: "center",
                        gap: 6,
                        width: 180,
                      }}
                    >
                      <span
                        style={{
                          fontFamily: fontFamily.mono,
                          fontSize: 24,
                          fontWeight: 700,
                          color: san.color,
                        }}
                      >
                        {san.abbr}
                      </span>
                      <span
                        style={{
                          fontFamily: fontFamily.sans,
                          fontSize: 14,
                          color: colors.muted,
                        }}
                      >
                        {san.label}
                      </span>
                    </div>
                  );
                })}
              </div>
            </FadeIn>

            {/* Fuzzing callout */}
            <FadeIn delay={120}>
              <div
                style={{
                  padding: "16px 24px",
                  borderRadius: 12,
                  backgroundColor: `${colors.success}08`,
                  border: `1px solid ${colors.success}20`,
                  display: "flex",
                  alignItems: "center",
                  gap: 16,
                }}
              >
                <span
                  style={{
                    fontFamily: fontFamily.mono,
                    fontSize: 18,
                    fontWeight: 600,
                    color: colors.success,
                  }}
                >
                  libFuzzer
                </span>
                <span
                  style={{
                    fontFamily: fontFamily.sans,
                    fontSize: 17,
                    color: colors.muted,
                  }}
                >
                  165 harnesses covering every parser, codec, and protocol handler
                </span>
              </div>
            </FadeIn>
          </div>

          {/* Right: conformance */}
          <div style={{ width: 460 }}>
            <FadeIn delay={50}>
              <div
                style={{
                  fontFamily: fontFamily.sans,
                  fontSize: 22,
                  fontWeight: 600,
                  color: colors.text,
                  marginBottom: 16,
                }}
              >
                Protocol Conformance
              </div>
              <FeatureList items={CONFORMANCE} delay={60} fontSize={20} />
            </FadeIn>
          </div>
        </div>
      </div>
    </Background>
  );
};
