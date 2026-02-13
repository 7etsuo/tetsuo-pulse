import React from "react";
import { useCurrentFrame, spring, useVideoConfig, interpolate, Easing } from "remotion";
import { colors } from "../lib/colors";
import { fontFamily } from "../lib/fonts";
import { stagger } from "../lib/animate";

interface Layer {
  label: string;
  color: string;
  fileCount?: number;
  sublabels?: string[];
}

interface LayerDiagramProps {
  layers: Layer[];
  delay?: number;
  staggerDelay?: number;
  highlightPath?: number[];
  width?: number;
  height?: number;
}

export const LayerDiagram: React.FC<LayerDiagramProps> = ({
  layers,
  delay = 0,
  staggerDelay = 8,
  highlightPath = [],
  width = 700,
  height = 600,
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const layerCount = layers.length;
  const layerHeight = 56;
  const layerGap = 16;
  const totalHeight = layerCount * layerHeight + (layerCount - 1) * layerGap;
  const startY = (height - totalHeight) / 2;
  const layerWidth = width - 180;
  const startX = 40;

  return (
    <svg width={width} height={height}>
      {layers.map((layer, i) => {
        const reverseIdx = layerCount - 1 - i;
        const d = stagger(reverseIdx, delay, staggerDelay);
        const isHighlighted = highlightPath.includes(i);

        const progress =
          frame < d
            ? 0
            : spring({
                frame: frame - d,
                fps,
                config: { damping: 100, stiffness: 200 },
              });

        const y = startY + i * (layerHeight + layerGap);

        const glowOpacity = isHighlighted
          ? interpolate(
              frame,
              [d + 20, d + 40, d + 60, d + 80],
              [0, 0.6, 0.3, 0.5],
              { extrapolateLeft: "clamp", extrapolateRight: "clamp" },
            )
          : 0;

        return (
          <g key={i} style={{ opacity: progress }}>
            {/* Glow for highlighted path */}
            {isHighlighted && (
              <rect
                x={startX - 4}
                y={y - 4}
                width={layerWidth + 8}
                height={layerHeight + 8}
                rx={14}
                fill="none"
                stroke={layer.color}
                strokeWidth={2}
                opacity={glowOpacity}
                filter="url(#glow)"
              />
            )}

            {/* Layer rect */}
            <rect
              x={startX}
              y={y}
              width={layerWidth * progress}
              height={layerHeight}
              rx={10}
              fill={`${layer.color}20`}
              stroke={`${layer.color}60`}
              strokeWidth={1}
            />

            {/* Label */}
            <text
              x={startX + 20}
              y={y + layerHeight / 2 + 1}
              fill={colors.text}
              fontFamily={fontFamily.sans}
              fontSize={20}
              fontWeight={600}
              dominantBaseline="middle"
              opacity={progress}
            >
              {layer.label}
            </text>

            {/* Sublabels */}
            {layer.sublabels && (
              <text
                x={startX + layerWidth - 20}
                y={y + layerHeight / 2 + 1}
                fill={colors.muted}
                fontFamily={fontFamily.mono}
                fontSize={14}
                textAnchor="end"
                dominantBaseline="middle"
                opacity={progress}
              >
                {layer.sublabels.join(" / ")}
              </text>
            )}

            {/* File count badge */}
            {layer.fileCount && (
              <g opacity={progress}>
                <rect
                  x={startX + layerWidth + 16}
                  y={y + (layerHeight - 28) / 2}
                  width={80}
                  height={28}
                  rx={14}
                  fill={`${layer.color}15`}
                  stroke={`${layer.color}40`}
                  strokeWidth={1}
                />
                <text
                  x={startX + layerWidth + 56}
                  y={y + layerHeight / 2 + 1}
                  fill={layer.color}
                  fontFamily={fontFamily.mono}
                  fontSize={13}
                  textAnchor="middle"
                  dominantBaseline="middle"
                >
                  {layer.fileCount} files
                </text>
              </g>
            )}

            {/* Connector arrow to layer above */}
            {i > 0 && (
              <line
                x1={startX + layerWidth / 2}
                y1={y}
                x2={startX + layerWidth / 2}
                y2={y - layerGap}
                stroke={colors.border}
                strokeWidth={1}
                opacity={progress * 0.5}
                strokeDasharray="4,4"
              />
            )}
          </g>
        );
      })}

      {/* SVG filter for glow */}
      <defs>
        <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="4" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>
    </svg>
  );
};
