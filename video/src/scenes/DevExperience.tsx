import React from "react";
import { useCurrentFrame } from "remotion";
import { Background } from "../components/Background";
import { FadeIn } from "../components/FadeIn";
import { CodeBlock } from "../components/CodeBlock";
import { Badge } from "../components/Badge";
import { colors } from "../lib/colors";
import { fontFamily } from "../lib/fonts";
import { fadeIn } from "../lib/animate";

const EXCEPTION_CODE = `volatile int result = 0;
Arena_T arena = Arena_new();

TRY {
    Socket_T sock = Socket_new(arena);
    Socket_connect(sock, "api.example.com", 443);
    SocketHTTP_request(sock, "GET", "/data");
    result = 1;
} EXCEPT(Socket_Failed) {
    fprintf(stderr, "Error: %s\\n",
            Socket_GetLastError());
} FINALLY {
    Arena_dispose(&arena);
} END_TRY;`;

const SIMPLE_CODE = `SocketSimple_Socket_T sock =
    Socket_simple_connect("api.example.com", 443);

if (!sock) {
    fprintf(stderr, "%s\\n",
            Socket_simple_error());
    return -1;
}

Socket_simple_http_get(sock, "/data");
char *body = Socket_simple_read_body(sock);

Socket_simple_close(sock);`;

export const DevExperience: React.FC = () => {
  const frame = useCurrentFrame();
  const arenaPhase = frame > 150;

  return (
    <Background>
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          padding: "60px 80px",
          gap: 28,
          height: "100%",
        }}
      >
        <FadeIn delay={3} duration={12}>
          <div style={{ fontFamily: fontFamily.sans, fontSize: 44, fontWeight: 700, color: colors.text }}>
            Developer Experience
          </div>
        </FadeIn>

        <FadeIn delay={10} duration={12}>
          <div style={{ fontFamily: fontFamily.sans, fontSize: 22, color: colors.muted }}>
            Two API styles — choose what fits your project
          </div>
        </FadeIn>

        <div style={{ display: "flex", gap: 32, flex: 1 }}>
          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 10 }}>
            <FadeIn delay={15}>
              <Badge label="Exception API" color={colors.primary} delay={15} fontSize={18} />
            </FadeIn>
            <FadeIn delay={20}>
              <CodeBlock code={EXCEPTION_CODE} animationType="typewriter" delay={22}
                charsPerFrame={4} fontSize={15} width={840} />
            </FadeIn>
          </div>

          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 10 }}>
            <FadeIn delay={80}>
              <Badge label="Simple API" color={colors.success} delay={80} fontSize={18} />
            </FadeIn>
            <FadeIn delay={85}>
              <CodeBlock code={SIMPLE_CODE} animationType="typewriter" delay={87}
                charsPerFrame={4} fontSize={15} width={840} />
            </FadeIn>
          </div>
        </div>

        {arenaPhase && (
          <FadeIn delay={155}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 32 }}>
              <div style={{ fontFamily: fontFamily.sans, fontSize: 20, color: colors.muted }}>Arena Lifecycle:</div>
              {["Arena_new()", "alloc / use", "Arena_dispose()"].map((step, i) => {
                const d = 158 + i * 8;
                const opacity = fadeIn(frame, d, 10);
                return (
                  <React.Fragment key={i}>
                    <div style={{
                      opacity, padding: "8px 20px", borderRadius: 8,
                      backgroundColor: `${colors.purple}12`, border: `1px solid ${colors.purple}30`,
                      fontFamily: fontFamily.mono, fontSize: 16, color: colors.purple,
                    }}>
                      {step}
                    </div>
                    {i < 2 && (
                      <svg width={28} height={20} style={{ opacity }}>
                        <path d="M4 10h16M16 5l4 5-4 5" stroke={colors.border} strokeWidth={1.5} fill="none" />
                      </svg>
                    )}
                  </React.Fragment>
                );
              })}
              <span style={{ fontFamily: fontFamily.sans, fontSize: 18, color: colors.success, marginLeft: 8 }}>
                All freed!
              </span>
            </div>
          </FadeIn>
        )}
      </div>
    </Background>
  );
};
