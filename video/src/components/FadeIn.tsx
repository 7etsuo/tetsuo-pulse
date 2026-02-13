import React from "react";
import { useCurrentFrame } from "remotion";
import { fadeIn, slideIn } from "../lib/animate";

interface FadeInProps {
  delay?: number;
  duration?: number;
  direction?: "up" | "down" | "left" | "right" | "none";
  distance?: number;
  children: React.ReactNode;
  style?: React.CSSProperties;
}

export const FadeIn: React.FC<FadeInProps> = ({
  delay = 0,
  duration = 20,
  direction = "up",
  distance = 30,
  children,
  style = {},
}) => {
  const frame = useCurrentFrame();
  const opacity = fadeIn(frame, delay, duration);

  const translateX =
    direction === "left" || direction === "right"
      ? slideIn(frame, direction, delay, distance, duration)
      : 0;
  const translateY =
    direction === "up" || direction === "down"
      ? slideIn(frame, direction, delay, distance, duration)
      : 0;

  return (
    <div
      style={{
        opacity,
        transform:
          direction === "none"
            ? undefined
            : `translate(${translateX}px, ${translateY}px)`,
        ...style,
      }}
    >
      {children}
    </div>
  );
};
