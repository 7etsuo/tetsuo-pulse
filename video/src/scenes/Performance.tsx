import React from "react";
import { useCurrentFrame, interpolate, Easing } from "remotion";
import { Background } from "../components/Background";
import { FadeIn } from "../components/FadeIn";
import { BarChart } from "../components/BarChart";
import { AnimatedCounter } from "../components/AnimatedCounter";
import { Badge } from "../components/Badge";
import { colors } from "../lib/colors";
import { fontFamily } from "../lib/fonts";
import { fadeIn, stagger } from "../lib/animate";

const THROUGHPUT_DATA = [
  { label: "Blocking I/O", value: 12000, color: colors.danger },
  { label: "epoll async", value: 85000, color: colors.primary },
  { label: "io_uring", value: 120000, color: colors.success },
];

const BACKEND_DATA = [
  { label: "poll(2)", value: 45000, color: colors.muted },
  { label: "epoll", value: 85000, color: colors.primary },
  { label: "kqueue", value: 82000, color: colors.purple },
  { label: "io_uring", value: 120000, color: colors.success },
];

const PERF_HIGHLIGHTS = [
  { label: "O(1)", desc: "connection pool lookup" },
  { label: "Zero-copy", desc: "with io_uring + registered buffers" },
  { label: "SQPOLL", desc: "kernel-side submission thread" },
  { label: "Batch", desc: "amortized submission overhead" },
];

export const Performance: React.FC = () => {
  const frame = useCurrentFrame();

  // Phase 1: throughput chart (0-200)
  // Phase 2: backend comparison (200-350)
  // Phase 3: highlights (350+)

  const showBackends = frame > 200;
  const showHighlights = frame > 350;

  return (
    <Background>
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          padding: "50px 80px",
          gap: 32,
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
            Performance
          </div>
        </FadeIn>

        <div style={{ display: "flex", gap: 60, flex: 1 }}>
          {/* Left: Charts */}
          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 24 }}>
            {/* Throughput chart */}
            {!showBackends && (
              <FadeIn delay={15}>
                <BarChart
                  data={THROUGHPUT_DATA}
                  maxValue={140000}
                  delay={25}
                  duration={50}
                  width={820}
                  height={280}
                  title="Throughput (requests/sec)"
                />
              </FadeIn>
            )}

            {/* Backend comparison */}
            {showBackends && (
              <FadeIn delay={200}>
                <BarChart
                  data={BACKEND_DATA}
                  maxValue={140000}
                  delay={210}
                  duration={50}
                  width={820}
                  height={340}
                  title="Platform Backend Comparison"
                />
              </FadeIn>
            )}
          </div>

          {/* Right: CPU gauge + highlights */}
          <div
            style={{
              width: 360,
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              gap: 32,
            }}
          >
            {/* CPU Usage gauge */}
            <FadeIn delay={40}>
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  gap: 8,
                  padding: 24,
                  backgroundColor: colors.bgCard,
                  borderRadius: 16,
                  border: `1px solid ${colors.border}`,
                  width: 240,
                }}
              >
                <span
                  style={{
                    fontFamily: fontFamily.sans,
                    fontSize: 16,
                    color: colors.muted,
                    textTransform: "uppercase",
                    letterSpacing: 2,
                  }}
                >
                  CPU Under Load
                </span>
                <div style={{ display: "flex", alignItems: "baseline" }}>
                  <AnimatedCounter
                    to={18}
                    delay={50}
                    duration={40}
                    fontSize={56}
                    color={colors.success}
                  />
                  <span
                    style={{
                      fontFamily: fontFamily.mono,
                      fontSize: 28,
                      color: colors.success,
                    }}
                  >
                    %
                  </span>
                </div>
              </div>
            </FadeIn>

            {/* 10x callout */}
            <FadeIn delay={100}>
              <div
                style={{
                  display: "flex",
                  alignItems: "baseline",
                  gap: 8,
                }}
              >
                <span
                  style={{
                    fontFamily: fontFamily.mono,
                    fontSize: 64,
                    fontWeight: 800,
                    color: colors.primary,
                  }}
                >
                  10x
                </span>
                <span
                  style={{
                    fontFamily: fontFamily.sans,
                    fontSize: 22,
                    color: colors.muted,
                  }}
                >
                  throughput
                </span>
              </div>
            </FadeIn>

            {/* Performance highlights */}
            {showHighlights && (
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                {PERF_HIGHLIGHTS.map((item, i) => {
                  const d = stagger(i, 360, 10);
                  const opacity = fadeIn(frame, d, 15);
                  return (
                    <div
                      key={i}
                      style={{
                        opacity,
                        display: "flex",
                        alignItems: "center",
                        gap: 12,
                      }}
                    >
                      <span
                        style={{
                          fontFamily: fontFamily.mono,
                          fontSize: 16,
                          fontWeight: 700,
                          color: colors.primary,
                          minWidth: 90,
                        }}
                      >
                        {item.label}
                      </span>
                      <span
                        style={{
                          fontFamily: fontFamily.sans,
                          fontSize: 16,
                          color: colors.muted,
                        }}
                      >
                        {item.desc}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>
    </Background>
  );
};
