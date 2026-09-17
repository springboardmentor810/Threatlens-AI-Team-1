import { HTMLAttributes } from "react";
import { cn } from "@/utils/cn";
import { Severity } from "@/types/threat.types";
import { SEVERITY_CONFIG } from "@/constants/severity";

interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  severity?: Severity | "safe" | "unscanned";
}

const SAFE_CONFIG = {
  label: "Safe",
  color: "text-accent-cyan",
  bg: "bg-accent-cyan/10",
  border: "border-accent-cyan/30",
  dot: "bg-accent-cyan",
};

/**
 * A file that was scanned but never scored - a non-PE upload, or the AI being
 * unavailable. Deliberately neutral rather than reusing "Safe": no verdict was
 * reached, and saying otherwise would overstate what the platform knows.
 */
const UNSCANNED_CONFIG = {
  label: "Unscanned",
  color: "text-muted",
  bg: "bg-white/5",
  border: "border-strong/30",
  dot: "bg-muted",
};

export default function Badge({ severity, className, children, ...props }: BadgeProps) {
  const config =
    severity === "safe"
      ? SAFE_CONFIG
      : severity === "unscanned"
        ? UNSCANNED_CONFIG
        : severity
          ? SEVERITY_CONFIG[severity]
          : null;

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium",
        config ? `${config.color} ${config.bg} ${config.border}` : "text-slate-300 bg-white/5 border-white/10",
        className
      )}
      {...props}
    >
      {config && <span className={cn("h-1.5 w-1.5 rounded-full", config.dot)} />}
      {children ?? config?.label}
    </span>
  );
}
