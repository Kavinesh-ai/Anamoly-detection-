import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { prisma } from "@/lib/prisma";
import type { RoleName } from "@prisma/client";

/**
 * Permission catalog — matches spec §6. Keep granular; every API route
 * must check one of these, never a bare role name, so permissions can be
 * re-mapped to roles without touching call sites.
 */
export const PERMISSIONS = {
  APPLICATIONS_READ: "applications.read",
  APPLICATIONS_WRITE: "applications.write",
  IAM_READ: "iam.read",
  IAM_WRITE: "iam.write",
  NETWORK_READ: "network.read",
  NETWORK_WRITE: "network.write",
  POLICIES_READ: "policies.read",
  POLICIES_WRITE: "policies.write",
  POLICIES_DEPLOY: "policies.deploy",
  KUBERNETES_READ: "kubernetes.read",
  KUBERNETES_WRITE: "kubernetes.write",
  INCIDENTS_READ: "incidents.read",
  INCIDENTS_MANAGE: "incidents.manage",
  INTEGRATIONS_READ: "integrations.read",
  INTEGRATIONS_MANAGE: "integrations.manage",
} as const;

type Permission = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

const ROLE_PERMISSIONS: Record<RoleName, Permission[]> = {
  SUPER_ADMIN: Object.values(PERMISSIONS),
  SECURITY_ADMIN: [
    PERMISSIONS.APPLICATIONS_READ,
    PERMISSIONS.IAM_READ,
    PERMISSIONS.IAM_WRITE,
    PERMISSIONS.NETWORK_READ,
    PERMISSIONS.NETWORK_WRITE,
    PERMISSIONS.POLICIES_READ,
    PERMISSIONS.POLICIES_WRITE,
    PERMISSIONS.POLICIES_DEPLOY,
    PERMISSIONS.INCIDENTS_READ,
    PERMISSIONS.INCIDENTS_MANAGE,
    PERMISSIONS.INTEGRATIONS_READ,
    PERMISSIONS.INTEGRATIONS_MANAGE,
  ],
  CLOUD_ENGINEER: [
    PERMISSIONS.APPLICATIONS_READ,
    PERMISSIONS.APPLICATIONS_WRITE,
    PERMISSIONS.IAM_READ,
    PERMISSIONS.NETWORK_READ,
    PERMISSIONS.NETWORK_WRITE,
    PERMISSIONS.POLICIES_READ,
    PERMISSIONS.INTEGRATIONS_READ,
  ],
  KUBERNETES_ENGINEER: [
    PERMISSIONS.APPLICATIONS_READ,
    PERMISSIONS.KUBERNETES_READ,
    PERMISSIONS.KUBERNETES_WRITE,
    PERMISSIONS.POLICIES_READ,
    PERMISSIONS.INTEGRATIONS_READ,
  ],
  SECURITY_ANALYST: [
    PERMISSIONS.APPLICATIONS_READ,
    PERMISSIONS.IAM_READ,
    PERMISSIONS.NETWORK_READ,
    PERMISSIONS.POLICIES_READ,
    PERMISSIONS.KUBERNETES_READ,
    PERMISSIONS.INCIDENTS_READ,
    PERMISSIONS.INCIDENTS_MANAGE,
    PERMISSIONS.INTEGRATIONS_READ,
  ],
  VIEWER: [
    PERMISSIONS.APPLICATIONS_READ,
    PERMISSIONS.IAM_READ,
    PERMISSIONS.NETWORK_READ,
    PERMISSIONS.POLICIES_READ,
    PERMISSIONS.KUBERNETES_READ,
    PERMISSIONS.INCIDENTS_READ,
    PERMISSIONS.INTEGRATIONS_READ,
  ],
};

export class UnauthorizedError extends Error {
  status = 401;
}
export class ForbiddenError extends Error {
  status = 403;
}

/**
 * Resolves the authenticated user's role within the requested organization
 * directly from the database — the organizationId in the URL/body is only
 * ever used to look up a real Membership row. It is never trusted on its
 * own, so org A can never read/write org B's data through a spoofed id.
 */
export async function requirePermission(
  organizationId: string,
  permission: Permission
) {
  const session = await getServerSession(authOptions);
  const userId = (session?.user as { id?: string } | undefined)?.id;
  if (!userId) throw new UnauthorizedError("Not authenticated.");

  const membership = await prisma.membership.findUnique({
    where: { userId_organizationId: { userId, organizationId } },
  });
  if (!membership) {
    throw new ForbiddenError("No membership in this organization.");
  }

  const allowed = ROLE_PERMISSIONS[membership.role].includes(permission);
  if (!allowed) {
    throw new ForbiddenError(`Role ${membership.role} lacks ${permission}.`);
  }

  return { userId, role: membership.role };
}
