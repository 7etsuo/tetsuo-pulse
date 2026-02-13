import React from "react";
import { useCurrentFrame, interpolate, Easing } from "remotion";
import { colors } from "../lib/colors";
import { fontFamily } from "../lib/fonts";
import { fadeIn } from "../lib/animate";

interface CodeBlockProps {
  code: string;
  animationType?: "typewriter" | "fade";
  delay?: number;
  charsPerFrame?: number;
  highlightLines?: number[];
  fontSize?: number;
  width?: number;
}

const TOKEN_COLORS: Record<string, string> = {
  keyword: "#c678dd",
  type: "#e5c07b",
  string: "#98c379",
  comment: "#5c6370",
  number: "#d19a66",
  function: "#61afef",
  macro: "#e06c75",
  punctuation: "#abb2bf",
  default: "#abb2bf",
};

const C_KEYWORDS = new Set([
  "if", "else", "while", "for", "return", "switch", "case", "break",
  "continue", "default", "do", "typedef", "struct", "enum", "union",
  "const", "volatile", "static", "extern", "void", "sizeof", "NULL",
  "true", "false", "goto",
]);

const C_TYPES = new Set([
  "int", "char", "long", "short", "unsigned", "signed", "float", "double",
  "size_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
  "int8_t", "int16_t", "int32_t", "int64_t", "bool", "ssize_t",
]);

interface Token {
  text: string;
  color: string;
}

function tokenizeLine(line: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;

  while (i < line.length) {
    // Comments
    if (line[i] === "/" && line[i + 1] === "/") {
      tokens.push({ text: line.slice(i), color: TOKEN_COLORS.comment });
      break;
    }
    if (line[i] === "/" && line[i + 1] === "*") {
      const end = line.indexOf("*/", i + 2);
      const commentEnd = end === -1 ? line.length : end + 2;
      tokens.push({ text: line.slice(i, commentEnd), color: TOKEN_COLORS.comment });
      i = commentEnd;
      continue;
    }

    // Strings
    if (line[i] === '"') {
      let j = i + 1;
      while (j < line.length && line[j] !== '"') {
        if (line[j] === "\\") j++;
        j++;
      }
      tokens.push({ text: line.slice(i, j + 1), color: TOKEN_COLORS.string });
      i = j + 1;
      continue;
    }

    // Preprocessor directives
    if (line[i] === "#") {
      const match = line.slice(i).match(/^#\w+/);
      if (match) {
        tokens.push({ text: match[0], color: TOKEN_COLORS.macro });
        i += match[0].length;
        continue;
      }
    }

    // Numbers
    if (/\d/.test(line[i]) && (i === 0 || !/\w/.test(line[i - 1]))) {
      const match = line.slice(i).match(/^(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?)/);
      if (match) {
        tokens.push({ text: match[0], color: TOKEN_COLORS.number });
        i += match[0].length;
        continue;
      }
    }

    // Words (identifiers, keywords, types)
    if (/[a-zA-Z_]/.test(line[i])) {
      const match = line.slice(i).match(/^[a-zA-Z_]\w*/);
      if (match) {
        const word = match[0];
        let color = TOKEN_COLORS.default;

        if (C_KEYWORDS.has(word)) {
          color = TOKEN_COLORS.keyword;
        } else if (C_TYPES.has(word)) {
          color = TOKEN_COLORS.type;
        } else if (word.endsWith("_T") || word.endsWith("_t")) {
          color = TOKEN_COLORS.type;
        } else if (i + word.length < line.length && line[i + word.length] === "(") {
          color = TOKEN_COLORS.function;
        } else if (word === word.toUpperCase() && word.length > 1) {
          color = TOKEN_COLORS.macro;
        }

        tokens.push({ text: word, color });
        i += word.length;
        continue;
      }
    }

    // Punctuation and operators
    tokens.push({ text: line[i], color: TOKEN_COLORS.punctuation });
    i++;
  }

  return tokens;
}

export const CodeBlock: React.FC<CodeBlockProps> = ({
  code,
  animationType = "fade",
  delay = 0,
  charsPerFrame = 1.5,
  highlightLines = [],
  fontSize = 20,
  width = 860,
}) => {
  const frame = useCurrentFrame();
  const lines = code.split("\n");

  const containerOpacity = fadeIn(frame, delay, 15);

  let visibleChars = Infinity;
  if (animationType === "typewriter") {
    const elapsed = Math.max(0, frame - delay);
    visibleChars = Math.floor(elapsed * charsPerFrame);
  }

  let charCount = 0;

  return (
    <div
      style={{
        opacity: containerOpacity,
        width,
        backgroundColor: "#1e1e2e",
        borderRadius: 12,
        border: `1px solid ${colors.border}`,
        padding: "20px 24px",
        overflow: "hidden",
      }}
    >
      {/* Window dots */}
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        {["#ff5f57", "#febc2e", "#28c840"].map((c) => (
          <div
            key={c}
            style={{
              width: 12,
              height: 12,
              borderRadius: "50%",
              backgroundColor: c,
            }}
          />
        ))}
      </div>

      {/* Code lines */}
      <div style={{ fontFamily: fontFamily.mono, fontSize, lineHeight: 1.6 }}>
        {lines.map((line, lineIdx) => {
          const isHighlighted = highlightLines.includes(lineIdx + 1);
          const tokens = tokenizeLine(line);

          const el = (
            <div
              key={lineIdx}
              style={{
                display: "flex",
                backgroundColor: isHighlighted ? `${colors.primary}15` : "transparent",
                borderLeft: isHighlighted ? `3px solid ${colors.primary}` : "3px solid transparent",
                paddingLeft: 12,
                marginLeft: -12,
              }}
            >
              {/* Line number */}
              <span
                style={{
                  color: "#5c6370",
                  minWidth: 36,
                  textAlign: "right",
                  marginRight: 16,
                  userSelect: "none",
                }}
              >
                {lineIdx + 1}
              </span>

              {/* Tokens */}
              <span>
                {tokens.map((token, tokenIdx) => {
                  if (animationType === "typewriter") {
                    const startChar = charCount;
                    charCount += token.text.length;
                    const visible = Math.max(
                      0,
                      Math.min(token.text.length, visibleChars - startChar),
                    );
                    if (visible <= 0) return null;
                    return (
                      <span key={tokenIdx} style={{ color: token.color }}>
                        {token.text.slice(0, visible)}
                      </span>
                    );
                  }
                  return (
                    <span key={tokenIdx} style={{ color: token.color }}>
                      {token.text}
                    </span>
                  );
                })}
              </span>
            </div>
          );

          // Account for newline in typewriter char counting
          if (animationType === "typewriter") charCount++;

          return el;
        })}
      </div>
    </div>
  );
};
