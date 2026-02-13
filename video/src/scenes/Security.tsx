import React from "react";
import { useCurrentFrame, spring, useVideoConfig } from "remotion";
import { Background } from "../components/Background";
import { FadeIn } from "../components/FadeIn";
import { colors } from "../lib/colors";
import { fontFamily } from "../lib/fonts";
import { fadeIn, stagger } from "../lib/animate";

const TLS_FEATURES = [
  "TLS 1.3", "SNI", "ALPN", "Cert Pinning", "kTLS", "0-RTT", "OCSP Stapling", "CRL",
];

const DNSSEC_CHAIN = [
  { label: "Root (.)", color: "#f59e0b" },
  { label: "TLD (.com)", color: colors.primary },
  { label: "Domain", color: colors.purple },
  { label: "Record", color: colors.success },
];

const DNS_TRANSPORTS = [
  { label: "DNS-over-TLS", rfc: "RFC 7858" },
  { label: "DNS-over-HTTPS", rfc: "RFC 8484" },
  { label: "DNSSEC Validation", rfc: "RFC 4033-4035" },
  { label: "DNS Cookies", rfc: "RFC 7873" },
];

export const Security: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  return (
    <Background>
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          padding: "60px 100px",
          gap: 36,
          height: "100%",
        }}
      >
        <FadeIn delay={3} duration={12}>
          <div style={{ fontFamily: fontFamily.sans, fontSize: 44, fontWeight: 700, color: colors.text }}>
            Security at Every Layer
          </div>
        </FadeIn>

        <div style={{ display: "flex", gap: 60, flex: 1 }}>
          {/* Left column */}
          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 28 }}>
            <FadeIn delay={10}>
              <div style={{ fontFamily: fontFamily.sans, fontSize: 22, fontWeight: 600, color: colors.text, marginBottom: 8 }}>
                TLS 1.3 / DTLS
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
                {TLS_FEATURES.map((feat, i) => {
                  const d = stagger(i, 15, 4);
                  const opacity = fadeIn(frame, d, 10);
                  return (
                    <div key={i} style={{
                      opacity, padding: "10px 18px", borderRadius: 10,
                      backgroundColor: `${colors.primary}12`, border: `1px solid ${colors.primary}30`,
                      fontFamily: fontFamily.mono, fontSize: 16, color: colors.primary, fontWeight: 500,
                    }}>
                      {feat}
                    </div>
                  );
                })}
              </div>
            </FadeIn>

            <FadeIn delay={60}>
              <div style={{ fontFamily: fontFamily.sans, fontSize: 22, fontWeight: 600, color: colors.text, marginBottom: 8 }}>
                DoS Protection
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 24 }}>
                <svg width={200} height={80}>
                  {[0, 1, 2, 3, 4].map((i) => {
                    const d = stagger(i, 65, 4);
                    const opacity = fadeIn(frame, d, 8);
                    const blocked = i >= 3;
                    return (
                      <g key={i}>
                        <rect x={i * 40} y={10} width={32} height={60} rx={6}
                          fill={blocked ? `${colors.danger}20` : `${colors.success}20`}
                          stroke={blocked ? colors.danger : colors.success} strokeWidth={1} opacity={opacity} />
                        <text x={i * 40 + 16} y={44} fill={blocked ? colors.danger : colors.success}
                          fontSize={14} fontFamily={fontFamily.mono} textAnchor="middle" dominantBaseline="middle" opacity={opacity}>
                          {blocked ? "X" : "OK"}
                        </text>
                      </g>
                    );
                  })}
                </svg>
                <span style={{ fontFamily: fontFamily.sans, fontSize: 18, color: colors.muted }}>
                  SYN cookies + rate limiting
                </span>
              </div>
            </FadeIn>
          </div>

          {/* Right column */}
          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 28 }}>
            <FadeIn delay={30}>
              <div style={{ fontFamily: fontFamily.sans, fontSize: 22, fontWeight: 600, color: colors.text, marginBottom: 8 }}>
                DNSSEC Chain of Trust
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
                {DNSSEC_CHAIN.map((node, i) => {
                  const d = stagger(i, 35, 8);
                  const progress = frame < d ? 0 : spring({ frame: frame - d, fps, config: { damping: 80, stiffness: 200 } });
                  return (
                    <React.Fragment key={i}>
                      <div style={{ opacity: progress, transform: `translateX(${i * 24}px)`, display: "flex", alignItems: "center", gap: 12 }}>
                        <div style={{ width: 16, height: 16, borderRadius: "50%", backgroundColor: node.color }} />
                        <span style={{ fontFamily: fontFamily.mono, fontSize: 18, color: node.color, fontWeight: 600 }}>
                          {node.label}
                        </span>
                      </div>
                      {i < DNSSEC_CHAIN.length - 1 && (
                        <div style={{ opacity: progress, marginLeft: i * 24 + 7, width: 2, height: 20, backgroundColor: colors.border }} />
                      )}
                    </React.Fragment>
                  );
                })}
              </div>
            </FadeIn>

            <FadeIn delay={80}>
              <div style={{ fontFamily: fontFamily.sans, fontSize: 22, fontWeight: 600, color: colors.text, marginBottom: 8 }}>
                Encrypted DNS
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {DNS_TRANSPORTS.map((t, i) => {
                  const d = stagger(i, 85, 6);
                  const opacity = fadeIn(frame, d, 10);
                  return (
                    <div key={i} style={{
                      opacity, display: "flex", alignItems: "center", justifyContent: "space-between",
                      padding: "10px 16px", borderRadius: 8, backgroundColor: colors.bgCard,
                      border: `1px solid ${colors.border}`, width: 380,
                    }}>
                      <span style={{ fontFamily: fontFamily.sans, fontSize: 17, color: colors.text }}>{t.label}</span>
                      <span style={{ fontFamily: fontFamily.mono, fontSize: 13, color: colors.muted }}>{t.rfc}</span>
                    </div>
                  );
                })}
              </div>
            </FadeIn>
          </div>
        </div>
      </div>
    </Background>
  );
};
