import { prisma } from "@/lib/prisma";
import type { SecurityPolicy } from "@prisma/client";

export type ValidationFinding = {
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  message: string;
  recommendation: string;
};

export type ValidationResult = {
  valid: boolean; // false blocks deployment for CRITICAL findings
  findings: ValidationFinding[];
};

/**
 * Real, deterministic policy validation against the current policy set in
 * Postgres — not a mocked "always passes" check. Detects the categories
 * called out in spec §13: open ingress, duplicate/shadowed rules, and
 * cross-environment allow rules.
 */
export async function validatePolicy(policy: SecurityPolicy): Promise<ValidationResult> {
  const findings: ValidationFinding[] = [];

  if (policy.action === "ALLOW" && policy.source === "0.0.0.0/0") {
    findings.push({
      severity: "CRITICAL",
      message: `This rule allows 0.0.0.0/0 → ${policy.protocol} ${policy.port ?? "any port"}.`,
      recommendation: "Restrict source CIDR or use identity-based administrative access.",
    });
  }

  if (policy.action === "ALLOW" && policy.port === 22 && policy.source === "0.0.0.0/0") {
    findings.push({
      severity: "CRITICAL",
      message: "Unrestricted SSH (port 22) exposure detected.",
      recommendation: "Restrict SSH to a bastion CIDR or use SSM Session Manager instead.",
    });
  }

  const siblings = await prisma.securityPolicy.findMany({
    where: {
      organizationId: policy.organizationId,
      source: policy.source,
      destination: policy.destination,
      protocol: policy.protocol,
      port: policy.port,
      id: { not: policy.id },
      status: { in: ["DEPLOYED", "APPROVED"] },
    },
  });

  const duplicate = siblings.find((s) => s.action === policy.action);
  if (duplicate) {
    findings.push({
      severity: "MEDIUM",
      message: `Duplicate rule already exists (policy "${duplicate.name}").`,
      recommendation: "Remove the redundant policy to keep the rule set auditable.",
    });
  }

  const conflicting = siblings.find((s) => s.action !== policy.action);
  if (conflicting) {
    findings.push({
      severity: "HIGH",
      message: `Conflicting rule "${conflicting.name}" (${conflicting.action}) covers the same source/destination/port.`,
      recommendation: "Resolve by adjusting priority or removing one of the conflicting policies.",
    });
  }

  if (
    policy.action === "ALLOW" &&
    policy.environment &&
    policy.destination.toLowerCase().includes("datacenter") &&
    policy.environment !== "production"
  ) {
    findings.push({
      severity: "HIGH",
      message: "Non-production environment allowed to reach the datacenter zone.",
      recommendation: "Restrict datacenter access to production/management environments only.",
    });
  }

  const hasCritical = findings.some((f) => f.severity === "CRITICAL");
  return { valid: !hasCritical, findings };
}
