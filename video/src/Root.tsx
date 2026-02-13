import React from "react";
import { Composition, registerRoot } from "remotion";
import { Video } from "./Video";
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

const SHARED = {
  width: 1920,
  height: 1080,
  fps: 30,
} as const;

export const RemotionRoot: React.FC = () => {
  return (
    <>
      {/* Full video */}
      <Composition
        id="FeatureShowcase"
        component={Video}
        durationInFrames={1770}
        {...SHARED}
      />

      {/* Individual scenes for preview/development */}
      <Composition
        id="Opening"
        component={Opening}
        durationInFrames={120}
        {...SHARED}
      />
      <Composition
        id="Problem"
        component={Problem}
        durationInFrames={165}
        {...SHARED}
      />
      <Composition
        id="ProtocolStack"
        component={ProtocolStack}
        durationInFrames={150}
        {...SHARED}
      />
      <Composition
        id="HTTP3Quic"
        component={HTTP3Quic}
        durationInFrames={210}
        {...SHARED}
      />
      <Composition
        id="Compression"
        component={Compression}
        durationInFrames={180}
        {...SHARED}
      />
      <Composition
        id="Security"
        component={Security}
        durationInFrames={165}
        {...SHARED}
      />
      <Composition
        id="Performance"
        component={Performance}
        durationInFrames={210}
        {...SHARED}
      />
      <Composition
        id="DevExperience"
        component={DevExperience}
        durationInFrames={240}
        {...SHARED}
      />
      <Composition
        id="Quality"
        component={Quality}
        durationInFrames={165}
        {...SHARED}
      />
      <Composition
        id="Closing"
        component={Closing}
        durationInFrames={165}
        {...SHARED}
      />
    </>
  );
};

registerRoot(RemotionRoot);
