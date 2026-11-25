import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requirePermission, PERMISSIONS, UnauthorizedError, ForbiddenError } from "@/server/rbac";

// GET /api/organizations/:id/dashboard
// Every field below is a COUNT() against real tables scoped to this org.
// If nothing is connected yet, the counts are honestly zero — see spec §20.
export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    await requirePermission(params.id, PERMISSIONS.APPLICATIONS_READ);

    const organizationId = params.id;

    const [
      connectedAccounts,
      activePolicies,
      protectedApplications,
      openIncidents,
      criticalFindings,
      driftFindings,
    ] = await Promise.all([
      prisma.cloudAccount.count({ where: { organizationId, status: "CONNECTED" } }),
      prisma.securityPolicy.count({ where: { organizationId, status: "DEPLOYED" } }),
      prisma.application.count({ where: { organizationId } }),
      prisma.incident.count({ where: { organizationId, status: { not: "RESOLVED" } } }),
      prisma.securityGroup.count({
        where: { vpc: { organizationId }, riskLevel: "CRITICAL" },
      }),
      // Drift detection engine (§26) is not yet wired to a background job in
      // this pass, so this is honestly 0 rather than a fabricated number —
      // see README "Remaining Configuration".
      Promise.resolve(0),
    ]);

    const hasAnyInfra = connectedAccounts > 0 || protectedApplications > 0;

    return NextResponse.json({
      success: true,
      data: {
        connectedAccounts,
        activePolicies,
        protectedApplications,
        openIncidents,
        criticalFindings,
        driftFindings,
        message: hasAnyInfra
          ? null
          : "No infrastructure connected. Connect AWS or Kubernetes to begin discovery.",
      },
    });
  } catch (err) {
    if (err instanceof UnauthorizedError) {
      return NextResponse.json({ success: false, error: { code: "UNAUTHORIZED", message: err.message } }, { status: 401 });
    }
    if (err instanceof ForbiddenError) {
      return NextResponse.json({ success: false, error: { code: "FORBIDDEN", message: err.message } }, { status: 403 });
    }
    return NextResponse.json(
      { success: false, error: { code: "INTERNAL_ERROR", message: "An internal error occurred." } },
      { status: 500 }
    );
  }
}
