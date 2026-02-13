import { interpolate, spring, Easing } from "remotion";

type Direction = "up" | "down" | "left" | "right";

export function fadeIn(
  frame: number,
  delay: number = 0,
  duration: number = 20,
): number {
  return interpolate(frame, [delay, delay + duration], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.out(Easing.cubic),
  });
}

export function slideIn(
  frame: number,
  direction: Direction = "up",
  delay: number = 0,
  distance: number = 40,
  duration: number = 20,
): number {
  const sign = direction === "down" || direction === "right" ? -1 : 1;
  const progress = interpolate(frame, [delay, delay + duration], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.out(Easing.cubic),
  });
  return sign * distance * (1 - progress);
}

export function stagger(index: number, baseDelay: number = 0, gap: number = 8): number {
  return baseDelay + index * gap;
}

export function springScale(
  frame: number,
  fps: number,
  delay: number = 0,
  damping: number = 100,
): number {
  if (frame < delay) return 0;
  return spring({
    frame: frame - delay,
    fps,
    config: { damping, stiffness: 200 },
  });
}

export function typewriter(
  text: string,
  frame: number,
  delay: number = 0,
  charsPerFrame: number = 1.5,
): string {
  const elapsed = Math.max(0, frame - delay);
  const chars = Math.floor(elapsed * charsPerFrame);
  return text.slice(0, chars);
}
