import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import { requirePermission, PERMISSIONS, UnauthorizedError, ForbiddenError } from "@/server/rbac";
import { validatePolicy } from "@/server/policy/validate";
import { writeAuditLog } from "@/server/audit";

const createSchema = z.object({
  organizationId: z.string().min(1),
  name: z.string().min(1),
  source: z.string().min(1),
  destination: z.string().min(1),
  protocol: z.string().min(1),
  port: z.number().int().min(0).max(65535).optional(),
  action: z.enum(["ALLOW", "DENY"]),
  environment: z.string().optional(),
  priority: z.number().int().optional(),
});

export async function GET(req: NextRequest) {
  const organizationId = new URL(req.url).searchParams.get("organizationId");
  if (!organizationId) {
    return NextResponse.json(
      { success: false, error: { code: "INVALID_INPUT", message: "organizationId is required." } },
      { status: 400 }
    );
  }
  try {
    await requirePermission(organizationId, PERMISSIONS.POLICIES_READ);
    const policies = await prisma.securityPolicy.findMany({
      where: { organizationId },
      orderBy: { priority: "asc" },
    });
    return NextResponse.json({ success: true, data: policies });
  } catch (err) {
    return errorResponse(err);
  }
}

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);
  const parsed = createSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { success: false, error: { code: "INVALID_INPUT", message: parsed.error.message } },
      { status: 400 }
    );
  }

  try {
    const { userId } = await requirePermission(parsed.data.organizationId, PERMISSIONS.POLICIES_WRITE);

    const policy = await prisma.securityPolicy.create({
      data: { ...parsed.data, port: parsed.data.port ?? null, status: "DRAFT" },
    });

    const validation = await validatePolicy(policy);

    await prisma.securityPolicy.update({
      where: { id: policy.id },
      data: { status: validation.valid ? "AWAITING_APPROVAL" : "DRAFT" },
    });

    await writeAuditLog({
      organizationId: parsed.data.organizationId,
      actorId: userId,
      action: "policy.created",
      resource: `SecurityPolicy:${policy.id}`,
      after: { policy, validation },
      result: "SUCCESS",
    });

    return NextResponse.json({ success: true, data: { policy, validation } });
  } catch (err) {
    return errorResponse(err);
  }
}

function errorResponse(err: unknown) {
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
