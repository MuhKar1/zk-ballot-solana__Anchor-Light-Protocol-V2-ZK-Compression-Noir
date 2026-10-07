"use client";

export function Stepper({ steps, current }: { steps: string[]; current: number }) {
  return (
    <ol className="stepper">
      {steps.map((step, i) => (
        <li key={step} className={i === current ? "active" : i < current ? "done" : ""}>
          {i + 1}. {step}
        </li>
      ))}
    </ol>
  );
}
