/**
 * DEVELOPMENT SEED DATA ONLY.
 *
 * This creates one organization and one Super Admin user so you can log in
 * and configure real integrations. It does NOT create any VPCs, security
 * groups, IAM roles, or clusters — those rows only ever come from real
 * discovery (src/server/aws/discovery.ts). A freshly seeded org's dashboard
 * will correctly show "No infrastructure connected."
 */
import { PrismaClient } from "@prisma/client";
import argon2 from "argon2";

const prisma = new PrismaClient();

async function main() {
  const org = await prisma.organization.upsert({
    where: { slug: "default" },
    create: { name: "Default Organization", slug: "default" },
    update: {},
  });

  const email = process.env.SEED_ADMIN_EMAIL ?? "admin@example.com";
  const password = process.env.SEED_ADMIN_PASSWORD;
  if (!password) {
    throw new Error(
      "Set SEED_ADMIN_PASSWORD before seeding — no default password is baked in."
    );
  }

  const passwordHash = await argon2.hash(password, { type: argon2.argon2id });

  const user = await prisma.user.upsert({
    where: { email },
    create: { email, passwordHash, emailVerifiedAt: new Date() },
    update: { passwordHash },
  });

  await prisma.membership.upsert({
    where: { userId_organizationId: { userId: user.id, organizationId: org.id } },
    create: { userId: user.id, organizationId: org.id, role: "SUPER_ADMIN" },
    update: { role: "SUPER_ADMIN" },
  });

  console.log(`Seeded organization "${org.slug}" and admin user "${email}".`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
