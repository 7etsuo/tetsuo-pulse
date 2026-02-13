import React from "react";
import { useCurrentFrame, interpolate, Easing } from "remotion";
import { Background } from "../components/Background";
import { FadeIn } from "../components/FadeIn";
import { FeatureList } from "../components/FeatureList";
import { colors } from "../lib/colors";
import { fontFamily } from "../lib/fonts";
import { fadeIn } from "../lib/animate";

export const Problem: React.FC = () => {
  const frame = useCurrentFrame();

  const transitionOpacity = fadeIn(frame, 300, 30);
  const transitionSlide = interpolate(frame, [300, 330], [40, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.out(Easing.cubic),
  });

  return (
    <Background>
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          height: "100%",
          padding: "0 140px",
          gap: 48,
        }}
      >
        {/* Headline */}
        <FadeIn delay={10} duration={25}>
          <div
            style={{
              fontFamily: fontFamily.sans,
              fontSize: 48,
              fontWeight: 700,
              color: colors.text,
              lineHeight: 1.2,
              maxWidth: 900,
            }}
          >
            Most C network libraries are
            <br />
            <span style={{ color: colors.danger }}>stuck in the HTTP/1.1 era</span>
          </div>
        </FadeIn>

        {/* Pain points */}
        <FadeIn delay={50}>
          <FeatureList
            delay={60}
            fontSize={28}
            items={[
              { text: "Need 5+ libraries for a modern network stack", available: false },
              { text: "External dependencies for compression", available: false },
              { text: "No native HTTP/2 or HTTP/3 support", available: false },
              { text: "No gRPC in C without massive frameworks", available: false },
              { text: "Fragmented error handling across libraries", available: false },
            ]}
          />
        </FadeIn>

        {/* Transition text */}
        <div
          style={{
            opacity: transitionOpacity,
            transform: `translateY(${transitionSlide}px)`,
            fontFamily: fontFamily.sans,
            fontSize: 36,
            fontWeight: 600,
            color: colors.primary,
            marginTop: 24,
          }}
        >
          What if one library did it all?
        </div>
      </div>
    </Background>
  );
};
