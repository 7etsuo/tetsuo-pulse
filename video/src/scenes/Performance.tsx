import React from "react";
import { useCurrentFrame } from "remotion";
import { Background } from "../components/Background";
import { FadeIn } from "../components/FadeIn";
import { BarChart } from "../components/BarChart";
import { AnimatedCounter } from "../components/AnimatedCounter";
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

  // Phase 1: throughput (0-80), Phase 2: backends (80+)
  const showBackends = frame > 80;
  const showHighlights = frame > 140;

  return (
    <Background>
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          padding: "50px 80px",
          gap: 24,
          height: "100%",
        }}
      >
        <FadeIn delay={3} duration={12}>
          <div style={{ fontFamily: fontFamily.sans, fontSize: 44, fontWeight: 700, color: colors.text }}>
            Performance
          </div>
        </FadeIn>

        <div style={{ display: "flex", gap: 60, flex: 1 }}>
          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 24 }}>
            {!showBackends && (
              <FadeIn delay={8}>
                <BarChart data={THROUGHPUT_DATA} maxValue={140000} delay={12} duration={40}
                  width={820} height={280} title="Throughput (requests/sec)" />
              </FadeIn>
            )}
            {showBackends && (
              <FadeIn delay={80}>
                <BarChart data={BACKEND_DATA} maxValue={140000} delay={85} duration={40}
                  width={820} height={340} title="Platform Backend Comparison" />
              </FadeIn>
            )}
          </div>

          <div style={{ width: 360, display: "flex", flexDirection: "column", alignItems: "center", gap: 28 }}>
            <FadeIn delay={20}>
              <div style={{
                display: "flex", flexDirection: "column", alignItems: "center", gap: 8,
                padding: 24, backgroundColor: colors.bgCard, borderRadius: 16,
                border: `1px solid ${colors.border}`, width: 240,
              }}>
                <span style={{
                  fontFamily: fontFamily.sans, fontSize: 16, color: colors.muted,
                  textTransform: "uppercase", letterSpacing: 2,
                }}>
                  CPU Under Load
                </span>
                <div style={{ display: "flex", alignItems: "baseline" }}>
                  <AnimatedCounter to={18} delay={25} duration={30} fontSize={56} color={colors.success} />
                  <span style={{ fontFamily: fontFamily.mono, fontSize: 28, color: colors.success }}>%</span>
                </div>
              </div>
            </FadeIn>

            <FadeIn delay={50}>
              <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
                <span style={{ fontFamily: fontFamily.mono, fontSize: 64, fontWeight: 800, color: colors.primary }}>10x</span>
                <span style={{ fontFamily: fontFamily.sans, fontSize: 22, color: colors.muted }}>throughput</span>
              </div>
            </FadeIn>

            {showHighlights && (
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {PERF_HIGHLIGHTS.map((item, i) => {
                  const d = stagger(i, 145, 6);
                  const opacity = fadeIn(frame, d, 10);
                  return (
                    <div key={i} style={{ opacity, display: "flex", alignItems: "center", gap: 12 }}>
                      <span style={{ fontFamily: fontFamily.mono, fontSize: 16, fontWeight: 700, color: colors.primary, minWidth: 90 }}>
                        {item.label}
                      </span>
                      <span style={{ fontFamily: fontFamily.sans, fontSize: 16, color: colors.muted }}>{item.desc}</span>
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
