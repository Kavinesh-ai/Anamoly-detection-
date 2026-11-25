import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import { requirePermission, PERMISSIONS, UnauthorizedError, ForbiddenError } from "@/server/rbac";
import { runAwsDiscovery } from "@/server/aws/discovery";
import { writeAuditLog } from "@/server/audit";

const querySchema = z.object({
  organizationId: z.string().min(1),
  cloudAccountId: z.string().min(1).optional(),
});

// GET /api/aws/vpcs?organizationId=...  -> real, currently-persisted VPCs.
export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const parsed = querySchema.safeParse({
    organizationId: url.searchParams.get("organizationId"),
    cloudAccountId: url.searchParams.get("cloudAccountId") ?? undefined,
  });
  if (!parsed.success) {
    return NextResponse.json(
      { success: false, error: { code: "INVALID_INPUT", message: parsed.error.message } },
      { status: 400 }
    );
  }

  try {
    await requirePermission(parsed.data.organizationId, PERMISSIONS.NETWORK_READ);

    const vpcs = await prisma.vPC.findMany({
      where: {
        organizationId: parsed.data.organizationId,
        ...(parsed.data.cloudAccountId ? { cloudAccountId: parsed.data.cloudAccountId } : {}),
      },
      include: { subnets: true, securityGroups: { include: { rules: true } } },
    });

    return NextResponse.json({ success: true, data: vpcs });
  } catch (err) {
    return errorResponse(err);
  }
}

const triggerSchema = z.object({
  organizationId: z.string().min(1),
  cloudAccountId: z.string().min(1),
});

// POST /api/aws/vpcs -> run real discovery against AWS now.
export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);
  const parsed = triggerSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { success: false, error: { code: "INVALID_INPUT", message: parsed.error.message } },
      { status: 400 }
    );
  }

  try {
    const { userId } = await requirePermission(parsed.data.organizationId, PERMISSIONS.NETWORK_WRITE);

    const result = await runAwsDiscovery(parsed.data.cloudAccountId);

    await writeAuditLog({
      organizationId: parsed.data.organizationId,
      actorId: userId,
      action: "aws.discovery.run",
      resource: `CloudAccount:${parsed.data.cloudAccountId}`,
      after: result,
      result: result.success ? "SUCCESS" : "FAILURE",
    });

    if (!result.success) {
      return NextResponse.json(
        { success: false, error: { code: "AWS_DISCOVERY_FAILED", message: result.error } },
        { status: 502 }
      );
    }

    return NextResponse.json({ success: true, data: result });
  } catch (err) {
    return errorResponse(err);
  }
}

function errorResponse(err: unknown) {
  if (err instanceof UnauthorizedError) {
    return NextResponse.json(
      { success: false, error: { code: "UNAUTHORIZED", message: err.message } },
      { status: 401 }
    );
  }
  if (err instanceof ForbiddenError) {
    return NextResponse.json(
      { success: false, error: { code: "FORBIDDEN", message: err.message } },
      { status: 403 }
    );
  }
  return NextResponse.json(
    {
      success: false,
      error: {
        code: "INTERNAL_ERROR",
        message: "An internal error occurred.", // never leak stack traces (spec §29)
      },
    },
    { status: 500 }
  );
}
