import React from "react";
import { useCurrentFrame } from "remotion";
import { Background } from "../components/Background";
import { FadeIn } from "../components/FadeIn";
import { StatCard } from "../components/StatCard";
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
          gap: 32,
          height: "100%",
        }}
      >
        <FadeIn delay={3} duration={12}>
          <div style={{ fontFamily: fontFamily.sans, fontSize: 44, fontWeight: 700, color: colors.text }}>
            Quality Infrastructure
          </div>
        </FadeIn>

        <div style={{ display: "flex", gap: 60, flex: 1 }}>
          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 24 }}>
            <div style={{ display: "flex", gap: 20 }}>
              <StatCard value={211} label="Tests" delay={8} color={colors.primary} width={220} />
              <StatCard value={165} label="Fuzz Harnesses" delay={14} color={colors.success} width={220} />
              <StatCard value={26} label="RFCs" delay={20} color={colors.purple} width={220} />
            </div>

            <FadeIn delay={35}>
              <div style={{ fontFamily: fontFamily.sans, fontSize: 20, color: colors.muted, marginBottom: 6 }}>
                Every PR runs with sanitizers:
              </div>
              <div style={{ display: "flex", gap: 12 }}>
                {SANITIZERS.map((san, i) => {
                  const d = stagger(i, 40, 6);
                  const opacity = fadeIn(frame, d, 10);
                  return (
                    <div key={i} style={{
                      opacity, padding: "16px 24px", borderRadius: 12,
                      backgroundColor: `${san.color}10`, border: `1px solid ${san.color}30`,
                      display: "flex", flexDirection: "column", alignItems: "center", gap: 6, width: 180,
                    }}>
                      <span style={{ fontFamily: fontFamily.mono, fontSize: 24, fontWeight: 700, color: san.color }}>{san.abbr}</span>
                      <span style={{ fontFamily: fontFamily.sans, fontSize: 14, color: colors.muted }}>{san.label}</span>
                    </div>
                  );
                })}
              </div>
            </FadeIn>

            <FadeIn delay={65}>
              <div style={{
                padding: "16px 24px", borderRadius: 12,
                backgroundColor: `${colors.success}08`, border: `1px solid ${colors.success}20`,
                display: "flex", alignItems: "center", gap: 16,
              }}>
                <span style={{ fontFamily: fontFamily.mono, fontSize: 18, fontWeight: 600, color: colors.success }}>libFuzzer</span>
                <span style={{ fontFamily: fontFamily.sans, fontSize: 17, color: colors.muted }}>
                  165 harnesses covering every parser, codec, and protocol handler
                </span>
              </div>
            </FadeIn>
          </div>

          <div style={{ width: 460 }}>
            <FadeIn delay={25}>
              <div style={{ fontFamily: fontFamily.sans, fontSize: 22, fontWeight: 600, color: colors.text, marginBottom: 12 }}>
                Protocol Conformance
              </div>
              <FeatureList items={CONFORMANCE} delay={30} fontSize={20} />
            </FadeIn>
          </div>
        </div>
      </div>
    </Background>
  );
};
