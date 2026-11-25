import type { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import argon2 from "argon2";
import { prisma } from "./prisma";
import { z } from "zod";

const credentialsSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

export const authOptions: NextAuthOptions = {
  session: {
    strategy: "database", // real server-side sessions, not just a signed JWT
    maxAge: 60 * 60 * 8, // 8 hours
  },
  pages: {
    signIn: "/login",
  },
  providers: [
    CredentialsProvider({
      name: "Email and password",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(raw) {
        const parsed = credentialsSchema.safeParse(raw);
        if (!parsed.success) return null;
        const { email, password } = parsed.data;

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user || !user.passwordHash) return null;

        const valid = await argon2.verify(user.passwordHash, password);
        if (!valid) return null;

        return { id: user.id, email: user.email };
      },
    }),
    // OAuth/OIDC providers (Google Workspace, Okta, etc.) can be added here
    // once the org supplies client credentials — architecture is ready,
    // nothing fake is added until real provider secrets exist.
  ],
  callbacks: {
    async session({ session, user }) {
      if (session.user) {
        (session.user as { id: string }).id = user.id;
        const memberships = await prisma.membership.findMany({
          where: { userId: user.id },
          select: { organizationId: true, role: true },
        });
        (session as unknown as { memberships: typeof memberships }).memberships =
          memberships;
      }
      return session;
    },
  },
};

export async function hashPassword(password: string): Promise<string> {
  // Argon2id per spec §7 — memory-hard, side-channel resistant.
  return argon2.hash(password, { type: argon2.argon2id });
}
