import React from "react";
import { useCurrentFrame, spring, useVideoConfig, interpolate } from "remotion";
import { Background } from "../components/Background";
import { FadeIn } from "../components/FadeIn";
import { Badge } from "../components/Badge";
import { FeatureList } from "../components/FeatureList";
import { colors } from "../lib/colors";
import { fontFamily } from "../lib/fonts";
import { fadeIn, stagger } from "../lib/animate";

const PIPELINE_STAGES = [
  { label: "Input", icon: "doc", color: colors.muted },
  { label: "LZ77", icon: "compress", color: colors.primary },
  { label: "Huffman", icon: "tree", color: colors.purple },
  { label: "Output", icon: "zip", color: colors.success },
];

export const Compression: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  return (
    <Background>
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          gap: 48,
          padding: "0 120px",
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
              textAlign: "center",
            }}
          >
            Native DEFLATE Compression
          </div>
        </FadeIn>

        <FadeIn delay={15}>
          <div
            style={{
              fontFamily: fontFamily.sans,
              fontSize: 24,
              color: colors.muted,
              textAlign: "center",
            }}
          >
            RFC 1951 implemented from scratch — zero external dependencies
          </div>
        </FadeIn>

        {/* Pipeline animation */}
        <div style={{ display: "flex", alignItems: "center", gap: 0, marginTop: 16 }}>
          {PIPELINE_STAGES.map((stage, i) => {
            const d = stagger(i, 40, 18);
            const progress =
              frame < d
                ? 0
                : spring({
                    frame: frame - d,
                    fps,
                    config: { damping: 80, stiffness: 180 },
                  });

            const arrowOpacity = fadeIn(frame, d + 10, 15);

            return (
              <React.Fragment key={i}>
                <div
                  style={{
                    opacity: progress,
                    transform: `scale(${progress})`,
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "center",
                    gap: 12,
                  }}
                >
                  {/* Stage box */}
                  <div
                    style={{
                      width: 160,
                      height: 100,
                      borderRadius: 16,
                      backgroundColor: `${stage.color}12`,
                      border: `2px solid ${stage.color}40`,
                      display: "flex",
                      flexDirection: "column",
                      alignItems: "center",
                      justifyContent: "center",
                      gap: 8,
                    }}
                  >
                    <svg width={32} height={32} viewBox="0 0 32 32">
                      {stage.icon === "doc" && (
                        <path
                          d="M8 4h10l6 6v18H8V4z M18 4v6h6"
                          stroke={stage.color}
                          strokeWidth={2}
                          fill="none"
                        />
                      )}
                      {stage.icon === "compress" && (
                        <g stroke={stage.color} strokeWidth={2} fill="none">
                          <path d="M6 16h20 M16 6v20" />
                          <path d="M10 10l12 12 M22 10L10 22" opacity={0.5} />
                        </g>
                      )}
                      {stage.icon === "tree" && (
                        <g stroke={stage.color} strokeWidth={2} fill="none">
                          <circle cx={16} cy={6} r={4} />
                          <circle cx={8} cy={22} r={4} />
                          <circle cx={24} cy={22} r={4} />
                          <line x1={16} y1={10} x2={8} y2={18} />
                          <line x1={16} y1={10} x2={24} y2={18} />
                        </g>
                      )}
                      {stage.icon === "zip" && (
                        <g stroke={stage.color} strokeWidth={2} fill="none">
                          <rect x={6} y={4} width={20} height={24} rx={3} />
                          <path d="M12 12h8 M12 16h8 M12 20h8" />
                        </g>
                      )}
                    </svg>
                    <span
                      style={{
                        fontFamily: fontFamily.mono,
                        fontSize: 16,
                        fontWeight: 600,
                        color: stage.color,
                      }}
                    >
                      {stage.label}
                    </span>
                  </div>
                </div>

                {/* Arrow between stages */}
                {i < PIPELINE_STAGES.length - 1 && (
                  <svg
                    width={60}
                    height={24}
                    style={{ opacity: arrowOpacity, marginTop: -24 }}
                  >
                    <path
                      d="M8 12h36M36 6l8 6-8 6"
                      stroke={colors.border}
                      strokeWidth={2}
                      fill="none"
                      strokeLinecap="round"
                    />
                  </svg>
                )}
              </React.Fragment>
            );
          })}
        </div>

        {/* Feature list */}
        <FadeIn delay={140}>
          <div style={{ display: "flex", gap: 60 }}>
            <FeatureList
              delay={150}
              fontSize={22}
              items={[
                { text: "Streaming inflate / deflate", available: true },
                { text: "Compression levels 0-9", available: true },
                { text: "gzip header parsing (RFC 1952)", available: true },
              ]}
            />
            <FeatureList
              delay={170}
              fontSize={22}
              items={[
                { text: "WebSocket permessage-deflate", available: true },
                { text: "HTTP Content-Encoding", available: true },
                { text: "Decompression bomb protection", available: true },
              ]}
            />
          </div>
        </FadeIn>

        {/* No deps badge */}
        <FadeIn delay={220} style={{ marginTop: 8 }}>
          <Badge
            label="No zlib, no brotli — pure C implementation"
            color={colors.success}
            delay={220}
            fontSize={20}
          />
        </FadeIn>
      </div>
    </Background>
  );
};
