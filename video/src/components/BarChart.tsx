import React from "react";
import { useCurrentFrame, spring, useVideoConfig, interpolate, Easing } from "remotion";
import { colors } from "../lib/colors";
import { fontFamily } from "../lib/fonts";
import { stagger } from "../lib/animate";

interface BarData {
  label: string;
  value: number;
  color: string;
}

interface BarChartProps {
  data: BarData[];
  maxValue?: number;
  delay?: number;
  duration?: number;
  width?: number;
  height?: number;
  title?: string;
}

export const BarChart: React.FC<BarChartProps> = ({
  data,
  maxValue: maxValueProp,
  delay = 0,
  duration = 45,
  width = 800,
  height = 400,
  title,
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const maxValue = maxValueProp ?? Math.max(...data.map((d) => d.value));
  const barHeight = 44;
  const barGap = 20;
  const labelWidth = 140;
  const valueWidth = 120;
  const chartWidth = width - labelWidth - valueWidth - 40;
  const totalBarsHeight = data.length * barHeight + (data.length - 1) * barGap;
  const startY = title ? 60 : 20;

  return (
    <svg width={width} height={height}>
      {title && (
        <text
          x={width / 2}
          y={30}
          fill={colors.text}
          fontFamily={fontFamily.sans}
          fontSize={24}
          fontWeight={600}
          textAnchor="middle"
        >
          {title}
        </text>
      )}

      {/* Grid lines */}
      {[0.25, 0.5, 0.75, 1].map((pct) => (
        <g key={pct}>
          <line
            x1={labelWidth + chartWidth * pct}
            y1={startY}
            x2={labelWidth + chartWidth * pct}
            y2={startY + totalBarsHeight}
            stroke={colors.border}
            strokeWidth={1}
            opacity={0.4}
            strokeDasharray="4,4"
          />
          <text
            x={labelWidth + chartWidth * pct}
            y={startY + totalBarsHeight + 24}
            fill={colors.muted}
            fontFamily={fontFamily.mono}
            fontSize={12}
            textAnchor="middle"
          >
            {Math.round(maxValue * pct).toLocaleString()}
          </text>
        </g>
      ))}

      {data.map((item, i) => {
        const d = stagger(i, delay, 8);
        const progress =
          frame < d
            ? 0
            : spring({
                frame: frame - d,
                fps,
                config: { damping: 80, stiffness: 150 },
              });

        const barWidth = (item.value / maxValue) * chartWidth * progress;
        const y = startY + i * (barHeight + barGap);

        const valueProgress = interpolate(
          frame,
          [d, d + duration],
          [0, item.value],
          { extrapolateLeft: "clamp", extrapolateRight: "clamp", easing: Easing.out(Easing.cubic) },
        );

        return (
          <g key={i}>
            {/* Label */}
            <text
              x={labelWidth - 12}
              y={y + barHeight / 2 + 1}
              fill={colors.text}
              fontFamily={fontFamily.sans}
              fontSize={16}
              fontWeight={500}
              textAnchor="end"
              dominantBaseline="middle"
              opacity={progress}
            >
              {item.label}
            </text>

            {/* Background track */}
            <rect
              x={labelWidth}
              y={y}
              width={chartWidth}
              height={barHeight}
              rx={8}
              fill={colors.bgCard}
              opacity={0.5}
            />

            {/* Animated bar */}
            <rect
              x={labelWidth}
              y={y}
              width={barWidth}
              height={barHeight}
              rx={8}
              fill={item.color}
              opacity={0.85}
            />

            {/* Gradient overlay for depth */}
            <rect
              x={labelWidth}
              y={y}
              width={barWidth}
              height={barHeight / 2}
              rx={8}
              fill="white"
              opacity={0.05}
            />

            {/* Value */}
            <text
              x={labelWidth + chartWidth + 16}
              y={y + barHeight / 2 + 1}
              fill={item.color}
              fontFamily={fontFamily.mono}
              fontSize={18}
              fontWeight={700}
              dominantBaseline="middle"
              opacity={progress}
            >
              {Math.round(valueProgress).toLocaleString()}
            </text>
          </g>
        );
      })}
    </svg>
  );
};
