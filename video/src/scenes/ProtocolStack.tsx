import React from "react";
import { useCurrentFrame, interpolate, Easing } from "remotion";
import { Background } from "../components/Background";
import { FadeIn } from "../components/FadeIn";
import { LayerDiagram } from "../components/LayerDiagram";
import { colors } from "../lib/colors";
import { fontFamily } from "../lib/fonts";
import { fadeIn } from "../lib/animate";

const LAYERS = [
  {
    label: "gRPC / WebSocket",
    color: colors.success,
    fileCount: 23,
    sublabels: ["Unary", "Streaming", "RFC 6455"],
  },
  {
    label: "HTTP/1.1 / HTTP/2 / HTTP/3",
    color: colors.primary,
    fileCount: 34,
    sublabels: ["HPACK", "QPACK", "RFC 9114"],
  },
  {
    label: "QUIC / TLS 1.3",
    color: colors.purple,
    fileCount: 54,
    sublabels: ["RFC 9000", "RFC 9001"],
  },
  {
    label: "UDP / TCP / Unix",
    color: "#f59e0b",
    fileCount: 24,
    sublabels: ["epoll", "kqueue", "io_uring"],
  },
];

export const ProtocolStack: React.FC = () => {
  const frame = useCurrentFrame();

  // Highlight the UDP→QUIC→HTTP/3→gRPC path after layers are built
  const highlightPath = frame > 200 ? [0, 1, 2, 3] : [];

  const pathLabelOpacity = fadeIn(frame, 220, 30);

  return (
    <Background>
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          gap: 24,
        }}
      >
        {/* Title */}
        <FadeIn delay={5} duration={20}>
          <div
            style={{
              fontFamily: fontFamily.sans,
              fontSize: 44,
              fontWeight: 700,
              color: colors.text,
              textAlign: "center",
            }}
          >
            Complete Protocol Stack
          </div>
        </FadeIn>

        <FadeIn delay={15}>
          <div
            style={{
              fontFamily: fontFamily.sans,
              fontSize: 22,
              color: colors.muted,
              textAlign: "center",
            }}
          >
            Every layer built from scratch in pure C
          </div>
        </FadeIn>

        {/* Layer diagram */}
        <LayerDiagram
          layers={LAYERS}
          delay={30}
          staggerDelay={15}
          highlightPath={highlightPath}
          width={800}
          height={380}
        />

        {/* Highlight path label */}
        <div
          style={{
            opacity: pathLabelOpacity,
            display: "flex",
            alignItems: "center",
            gap: 16,
          }}
        >
          <svg width={24} height={24} viewBox="0 0 24 24">
            <path
              d="M5 12h14M12 5l7 7-7 7"
              stroke={colors.success}
              strokeWidth={2}
              fill="none"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          <span
            style={{
              fontFamily: fontFamily.sans,
              fontSize: 22,
              fontWeight: 600,
              color: colors.success,
            }}
          >
            UDP &rarr; QUIC &rarr; HTTP/3 &rarr; gRPC — all native
          </span>
        </div>
      </div>
    </Background>
  );
};
