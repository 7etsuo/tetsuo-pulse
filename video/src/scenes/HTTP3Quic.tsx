import React from "react";
import { useCurrentFrame } from "remotion";
import { Background } from "../components/Background";
import { FadeIn } from "../components/FadeIn";
import { CodeBlock } from "../components/CodeBlock";
import { Badge } from "../components/Badge";
import { FeatureList } from "../components/FeatureList";
import { colors } from "../lib/colors";
import { fontFamily } from "../lib/fonts";
import { fadeIn, stagger } from "../lib/animate";

const QUIC_CODE = `SocketQUIC_Conn_T conn = SocketQUIC_Conn_new(arena);

// 0-RTT early data for instant requests
SocketQUIC_Conn_enable_0rtt(conn, session);
SocketQUIC_Conn_connect(conn, "api.example.com", 443);

// Multiplexed streams over single connection
SocketQUIC_Stream_T s1 = SocketQUIC_Stream_open(conn);
SocketQUIC_Stream_T s2 = SocketQUIC_Stream_open(conn);

// HTTP/3 requests over QUIC
SocketHTTP3_request(s1, "GET", "/data");
SocketHTTP3_request(s2, "POST", "/upload");`;

const STATE_MACHINE = [
  { label: "IDLE", color: colors.muted },
  { label: "HANDSHAKE", color: "#f59e0b" },
  { label: "READY", color: colors.success },
  { label: "CLOSING", color: colors.danger },
  { label: "CLOSED", color: colors.muted },
];

export const HTTP3Quic: React.FC = () => {
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
          <div
            style={{
              fontFamily: fontFamily.sans,
              fontSize: 44,
              fontWeight: 700,
              color: colors.text,
            }}
          >
            HTTP/3 &amp; QUIC
          </div>
        </FadeIn>

        <div style={{ display: "flex", gap: 60, flex: 1 }}>
          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 24 }}>
            <FadeIn delay={10}>
              <FeatureList
                delay={12}
                fontSize={24}
                items={[
                  { text: "0-RTT connection resumption", available: true },
                  { text: "Path migration (network switch)", available: true },
                  { text: "Stream multiplexing (no HOL blocking)", available: true },
                  { text: "QPACK two-stream header compression", available: true },
                  { text: "Connection ID rotation", available: true },
                ]}
              />
            </FadeIn>

            <FadeIn delay={60}>
              <div
                style={{
                  fontFamily: fontFamily.sans,
                  fontSize: 18,
                  color: colors.muted,
                  marginBottom: 8,
                }}
              >
                Connection State Machine
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                {STATE_MACHINE.map((state, i) => {
                  const d = stagger(i, 65, 6);
                  const opacity = fadeIn(frame, d, 10);
                  return (
                    <React.Fragment key={i}>
                      <div
                        style={{
                          opacity,
                          padding: "8px 16px",
                          borderRadius: 8,
                          backgroundColor: `${state.color}15`,
                          border: `1px solid ${state.color}40`,
                          fontFamily: fontFamily.mono,
                          fontSize: 14,
                          color: state.color,
                          fontWeight: 600,
                        }}
                      >
                        {state.label}
                      </div>
                      {i < STATE_MACHINE.length - 1 && (
                        <svg width={20} height={20} style={{ opacity }}>
                          <path
                            d="M4 10h12M12 6l4 4-4 4"
                            stroke={colors.border}
                            strokeWidth={1.5}
                            fill="none"
                          />
                        </svg>
                      )}
                    </React.Fragment>
                  );
                })}
              </div>
            </FadeIn>
          </div>

          <div style={{ flex: 1 }}>
            <FadeIn delay={25}>
              <CodeBlock
                code={QUIC_CODE}
                animationType="typewriter"
                delay={30}
                charsPerFrame={4}
                fontSize={16}
                width={780}
              />
            </FadeIn>
          </div>
        </div>

        <FadeIn delay={130} style={{ alignSelf: "center" }}>
          <Badge
            label="First C library with gRPC over HTTP/3"
            color={colors.success}
            delay={130}
            fontSize={22}
          />
        </FadeIn>
      </div>
    </Background>
  );
};
