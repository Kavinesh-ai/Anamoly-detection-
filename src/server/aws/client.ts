import { STSClient, AssumeRoleCommand } from "@aws-sdk/client-sts";
import { EC2Client } from "@aws-sdk/client-ec2";
import { IAMClient } from "@aws-sdk/client-iam";
import { prisma } from "@/lib/prisma";
import { decryptSecret } from "@/lib/crypto";

export class AwsIntegrationError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

/**
 * Resolves temporary AWS credentials for a CloudAccount.
 *
 * Preferred path (spec §8 Option A): STS AssumeRole using a long-lived
 * access key stored encrypted in IntegrationCredential — that access key
 * belongs to a narrow "trust broker" IAM user whose only permission is
 * sts:AssumeRole into the customer's Discovery/Enforcement roles. In a real
 * AWS-hosted deployment this is swapped for the instance/task's own IAM
 * role and AssumeRole is called directly with no stored secret at all.
 *
 * If no CloudAccount/credential exists yet, this throws — callers must
 * surface that as NOT_CONFIGURED, never as connected.
 */
export async function getAwsClientsForAccount(cloudAccountId: string) {
  const account = await prisma.cloudAccount.findUnique({
    where: { id: cloudAccountId },
    include: { credential: true },
  });

  if (!account) {
    throw new AwsIntegrationError("AWS_ACCOUNT_NOT_FOUND", "No such cloud account.");
  }
  if (!account.credential) {
    throw new AwsIntegrationError(
      "AWS_NOT_CONFIGURED",
      "This AWS integration has no stored credentials yet. Configure it under /integrations."
    );
  }
  if (!account.roleArn) {
    throw new AwsIntegrationError(
      "AWS_NOT_CONFIGURED",
      "No IAM role ARN configured for AssumeRole."
    );
  }

  let accessKeyId: string;
  let secretAccessKey: string;
  try {
    const decrypted = decryptSecret(account.credential);
    const parsed = JSON.parse(decrypted) as {
      accessKeyId: string;
      secretAccessKey: string;
    };
    accessKeyId = parsed.accessKeyId;
    secretAccessKey = parsed.secretAccessKey;
  } catch {
    throw new AwsIntegrationError(
      "AWS_CREDENTIAL_DECRYPT_FAILED",
      "Stored AWS credential could not be decrypted. Re-enter integration credentials."
    );
  }

  const sts = new STSClient({
    region: account.region,
    credentials: { accessKeyId, secretAccessKey },
  });

  let assumed;
  try {
    assumed = await sts.send(
      new AssumeRoleCommand({
        RoleArn: account.roleArn,
        RoleSessionName: `sentinelmesh-${account.id}`,
        DurationSeconds: 900,
      })
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new AwsIntegrationError(
      "AWS_ASSUME_ROLE_FAILED",
      `Unable to authenticate with AWS: ${message}`
    );
  }

  const creds = assumed.Credentials;
  if (!creds?.AccessKeyId || !creds.SecretAccessKey || !creds.SessionToken) {
    throw new AwsIntegrationError(
      "AWS_ASSUME_ROLE_FAILED",
      "AssumeRole did not return usable temporary credentials."
    );
  }

  const sessionCreds = {
    accessKeyId: creds.AccessKeyId,
    secretAccessKey: creds.SecretAccessKey,
    sessionToken: creds.SessionToken,
  };

  return {
    ec2: new EC2Client({ region: account.region, credentials: sessionCreds }),
    iam: new IAMClient({ region: account.region, credentials: sessionCreds }),
  };
}
