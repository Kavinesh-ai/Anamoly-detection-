import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET() {
  const status: Record<string, string> = { application: "ok" };

  try {
    await prisma.$queryRaw`SELECT 1`;
    status.database = "ok";
  } catch {
    status.database = "unreachable";
  }

  const redisUrl = process.env.REDIS_URL;
  if (redisUrl) {
    status.redis = "configured"; // real ping happens in the worker process
  } else {
    status.redis = "not_configured";
  }

  const healthy = status.database === "ok";
  return NextResponse.json({ success: healthy, status }, { status: healthy ? 200 : 503 });
}
