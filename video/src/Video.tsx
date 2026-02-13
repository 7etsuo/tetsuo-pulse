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
 *   Opening:       120 frames  (4s)
 *   Problem:       165 frames  (5.5s)
 *   ProtocolStack: 150 frames  (5s)
 *   HTTP3Quic:     210 frames  (7s)
 *   Compression:   180 frames  (6s)
 *   Security:      165 frames  (5.5s)
 *   Performance:   210 frames  (7s)
 *   DevExperience: 240 frames  (8s)
 *   Quality:       165 frames  (5.5s)
 *   Closing:       165 frames  (5.5s)
 *   ────────────────────────────
 *   Total:         1770 frames (59s)
 */

export const Video: React.FC = () => {
  return (
    <Series>
      <Series.Sequence durationInFrames={120}>
        <Opening />
      </Series.Sequence>
      <Series.Sequence durationInFrames={165}>
        <Problem />
      </Series.Sequence>
      <Series.Sequence durationInFrames={150}>
        <ProtocolStack />
      </Series.Sequence>
      <Series.Sequence durationInFrames={210}>
        <HTTP3Quic />
      </Series.Sequence>
      <Series.Sequence durationInFrames={180}>
        <Compression />
      </Series.Sequence>
      <Series.Sequence durationInFrames={165}>
        <Security />
      </Series.Sequence>
      <Series.Sequence durationInFrames={210}>
        <Performance />
      </Series.Sequence>
      <Series.Sequence durationInFrames={240}>
        <DevExperience />
      </Series.Sequence>
      <Series.Sequence durationInFrames={165}>
        <Quality />
      </Series.Sequence>
      <Series.Sequence durationInFrames={165}>
        <Closing />
      </Series.Sequence>
    </Series>
  );
};
