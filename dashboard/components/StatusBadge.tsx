import type { Classification, OutputTag } from "@/models";

export function StatusBadge({
  value,
  tone,
}: {
  value: string;
  tone?: "neutral" | "good" | "warning" | "danger" | "ai" | "analyst";
}) {
  return <span className={`badge badge-${tone ?? "neutral"}`}>{value.replaceAll("_", " ")}</span>;
}

const classificationTone: Record<Classification, Parameters<typeof StatusBadge>[0]["tone"]> = {
  OBSERVED_FACT: "good",
  DETERMINISTIC_CORRELATION: "neutral",
  AI_INFERENCE: "ai",
  ANALYST_ACTION: "analyst",
  SYSTEM_ACTION: "warning",
};

export function ClassificationBadge({ value }: { value: Classification }) {
  return <StatusBadge value={value} tone={classificationTone[value]} />;
}

export function OutputTagBadge({ value }: { value?: OutputTag }) {
  if (!value) return null;
  return (
    <StatusBadge
      value={value}
      tone={
        value === "ANALYST_MESSAGE"
          ? "analyst"
          : value === "AI_GENERATED_INTERACTION"
            ? "ai"
            : value === "UNTRUSTED_INTRUDER_OUTPUT"
              ? "danger"
              : "neutral"
      }
    />
  );
}
