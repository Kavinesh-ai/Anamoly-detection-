import { prisma } from "@/lib/prisma";

export async function writeAuditLog(entry: {
  organizationId: string;
  actorId?: string;
  action: string;
  resource: string;
  before?: unknown;
  after?: unknown;
  ip?: string;
  result: "SUCCESS" | "FAILURE";
}) {
  await prisma.auditLog.create({
    data: {
      organizationId: entry.organizationId,
      actorId: entry.actorId,
      action: entry.action,
      resource: entry.resource,
      before: entry.before as never,
      after: entry.after as never,
      ip: entry.ip,
      result: entry.result,
    },
  });
}
