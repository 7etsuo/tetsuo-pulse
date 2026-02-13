import React from "react";
import { useCurrentFrame } from "remotion";
import { colors } from "../lib/colors";
import { fontFamily } from "../lib/fonts";
import { fadeIn, slideIn, stagger } from "../lib/animate";

interface FeatureItem {
  text: string;
  available: boolean;
}

interface FeatureListProps {
  items: FeatureItem[];
  delay?: number;
  fontSize?: number;
}

export const FeatureList: React.FC<FeatureListProps> = ({
  items,
  delay = 0,
  fontSize = 28,
}) => {
  const frame = useCurrentFrame();

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {items.map((item, i) => {
        const d = stagger(i, delay, 10);
        const opacity = fadeIn(frame, d, 15);
        const translateX = slideIn(frame, "left", d, 20, 15);

        return (
          <div
            key={i}
            style={{
              opacity,
              transform: `translateX(${translateX}px)`,
              display: "flex",
              alignItems: "center",
              gap: 16,
            }}
          >
            <svg width={28} height={28} viewBox="0 0 28 28">
              {item.available ? (
                <g>
                  <circle cx={14} cy={14} r={14} fill={`${colors.success}20`} />
                  <path
                    d="M8 14l4 4 8-8"
                    stroke={colors.success}
                    strokeWidth={2.5}
                    fill="none"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </g>
              ) : (
                <g>
                  <circle cx={14} cy={14} r={14} fill={`${colors.danger}20`} />
                  <path
                    d="M9 9l10 10M19 9l-10 10"
                    stroke={colors.danger}
                    strokeWidth={2.5}
                    fill="none"
                    strokeLinecap="round"
                  />
                </g>
              )}
            </svg>
            <span
              style={{
                fontFamily: fontFamily.sans,
                fontSize,
                color: item.available ? colors.text : colors.muted,
              }}
            >
              {item.text}
            </span>
          </div>
        );
      })}
    </div>
  );
};
