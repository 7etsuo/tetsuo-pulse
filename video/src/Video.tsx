import React from "react";
import { Series } from "remotion";
import { Opening } from "./scenes/Opening";
import { Problem } from "./scenes/Problem";
import { ProtocolStack } from "./scenes/ProtocolStack";
import { HTTP3Quic } from "./scenes/HTTP3Quic";
import { Compression } from "./scenes/Compression";
import { Security } from "./scenes/Security";
import { Performance } from "./scenes/Performance";
import { DevExperience } from "./scenes/DevExperience";
import { Quality } from "./scenes/Quality";
import { Closing } from "./scenes/Closing";

/*
 * Scene timings (30 fps):
 *   Opening:       300 frames  (10s)
 *   Problem:       450 frames  (15s)
 *   ProtocolStack: 1050 frames (35s)
 *   HTTP3Quic:     1800 frames (60s)
 *   Compression:   900 frames  (30s)
 *   Security:      1500 frames (50s)
 *   Performance:   1500 frames (50s)
 *   DevExperience: 1200 frames (40s)
 *   Quality:       1200 frames (40s)
 *   Closing:       900 frames  (30s)
 *   ────────────────────────────
 *   Total:         10800 frames (360s / 6min)
 */

export const Video: React.FC = () => {
  return (
    <Series>
      <Series.Sequence durationInFrames={300}>
        <Opening />
      </Series.Sequence>
      <Series.Sequence durationInFrames={450}>
        <Problem />
      </Series.Sequence>
      <Series.Sequence durationInFrames={1050}>
        <ProtocolStack />
      </Series.Sequence>
      <Series.Sequence durationInFrames={1800}>
        <HTTP3Quic />
      </Series.Sequence>
      <Series.Sequence durationInFrames={900}>
        <Compression />
      </Series.Sequence>
      <Series.Sequence durationInFrames={1500}>
        <Security />
      </Series.Sequence>
      <Series.Sequence durationInFrames={1500}>
        <Performance />
      </Series.Sequence>
      <Series.Sequence durationInFrames={1200}>
        <DevExperience />
      </Series.Sequence>
      <Series.Sequence durationInFrames={1200}>
        <Quality />
      </Series.Sequence>
      <Series.Sequence durationInFrames={900}>
        <Closing />
      </Series.Sequence>
    </Series>
  );
};
