import {
  DescribeVpcsCommand,
  DescribeSubnetsCommand,
  DescribeSecurityGroupsCommand,
} from "@aws-sdk/client-ec2";
import { prisma } from "@/lib/prisma";
import { getAwsClientsForAccount, AwsIntegrationError } from "./client";

/**
 * Runs real AWS discovery for one CloudAccount and upserts the results into
 * Postgres. This is the only path by which VPC/SecurityGroup rows are ever
 * created — there is no seed/demo path that writes into these tables in a
 * way indistinguishable from real discovery (see prisma/seed.ts).
 *
 * On any AWS error, the CloudAccount status is set to ERROR with the real
 * message and the function returns that failure — callers must not report
 * success in that case.
 */
export async function runAwsDiscovery(cloudAccountId: string) {
  try {
    const { ec2 } = await getAwsClientsForAccount(cloudAccountId);

    const vpcsResp = await ec2.send(new DescribeVpcsCommand({}));
    const vpcs = vpcsResp.Vpcs ?? [];

    for (const vpc of vpcs) {
      if (!vpc.VpcId) continue;

      const account = await prisma.cloudAccount.findUniqueOrThrow({
        where: { id: cloudAccountId },
      });

      const vpcRow = await prisma.vPC.upsert({
        where: { cloudAccountId_vpcId: { cloudAccountId, vpcId: vpc.VpcId } },
        create: {
          organizationId: account.organizationId,
          cloudAccountId,
          vpcId: vpc.VpcId,
          cidrBlock: vpc.CidrBlock ?? "",
          region: account.region,
        },
        update: { cidrBlock: vpc.CidrBlock ?? "" },
      });

      const subnetsResp = await ec2.send(
        new DescribeSubnetsCommand({
          Filters: [{ Name: "vpc-id", Values: [vpc.VpcId] }],
        })
      );
      for (const subnet of subnetsResp.Subnets ?? []) {
        if (!subnet.SubnetId) continue;
        await prisma.subnet.upsert({
          where: { vpcId_subnetId: { vpcId: vpcRow.id, subnetId: subnet.SubnetId } },
          create: {
            vpcId: vpcRow.id,
            subnetId: subnet.SubnetId,
            cidrBlock: subnet.CidrBlock ?? "",
            az: subnet.AvailabilityZone ?? "",
          },
          update: {
            cidrBlock: subnet.CidrBlock ?? "",
            az: subnet.AvailabilityZone ?? "",
          },
        });
      }

      const sgResp = await ec2.send(
        new DescribeSecurityGroupsCommand({
          Filters: [{ Name: "vpc-id", Values: [vpc.VpcId] }],
        })
      );
      for (const sg of sgResp.SecurityGroups ?? []) {
        if (!sg.GroupId) continue;

        const ingressRules = (sg.IpPermissions ?? []).flatMap((perm) =>
          (perm.IpRanges ?? []).map((r) => ({
            direction: "INGRESS" as const,
            protocol: perm.IpProtocol ?? "-1",
            fromPort: perm.FromPort ?? null,
            toPort: perm.ToPort ?? null,
            cidr: r.CidrIp ?? null,
          }))
        );
        const egressRules = (sg.IpPermissionsEgress ?? []).flatMap((perm) =>
          (perm.IpRanges ?? []).map((r) => ({
            direction: "EGRESS" as const,
            protocol: perm.IpProtocol ?? "-1",
            fromPort: perm.FromPort ?? null,
            toPort: perm.ToPort ?? null,
            cidr: r.CidrIp ?? null,
          }))
        );
        const allRules = [...ingressRules, ...egressRules];

        // Least-privilege risk heuristic (spec §13): flag any 0.0.0.0/0 ingress.
        const hasOpenIngress = ingressRules.some((r) => r.cidr === "0.0.0.0/0");
        const riskLevel = hasOpenIngress ? "CRITICAL" : "LOW";

        const sgRow = await prisma.securityGroup.upsert({
          where: { vpcId_groupId: { vpcId: vpcRow.id, groupId: sg.GroupId } },
          create: {
            vpcId: vpcRow.id,
            groupId: sg.GroupId,
            name: sg.GroupName ?? sg.GroupId,
            description: sg.Description,
            riskLevel,
          },
          update: {
            name: sg.GroupName ?? sg.GroupId,
            description: sg.Description,
            riskLevel,
          },
        });

        await prisma.securityGroupRule.deleteMany({ where: { securityGroupId: sgRow.id } });
        if (allRules.length > 0) {
          await prisma.securityGroupRule.createMany({
            data: allRules.map((r) => ({ ...r, securityGroupId: sgRow.id })),
          });
        }
      }
    }

    await prisma.cloudAccount.update({
      where: { id: cloudAccountId },
      data: { status: "CONNECTED", lastCheckedAt: new Date(), lastError: null },
    });

    return { success: true as const, vpcCount: vpcs.length };
  } catch (err) {
    const message =
      err instanceof AwsIntegrationError
        ? err.message
        : err instanceof Error
        ? err.message
        : "Unknown AWS discovery failure.";

    await prisma.cloudAccount.update({
      where: { id: cloudAccountId },
      data: { status: "ERROR", lastCheckedAt: new Date(), lastError: message },
    });

    return { success: false as const, error: message };
  }
}
