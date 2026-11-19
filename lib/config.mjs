// Reads the deployed stack's outputs so nothing is hard-coded.
import { CloudFormationClient, DescribeStacksCommand } from '@aws-sdk/client-cloudformation';

export const region = process.env.AWS_REGION ?? 'us-east-1';
export const stackName = process.env.STACK_NAME ?? 'sandbox-janitor';

let cached;
export async function outputs() {
  if (cached) return cached;
  const cfn = new CloudFormationClient({ region });
  const r = await cfn.send(new DescribeStacksCommand({ StackName: stackName }));
  cached = Object.fromEntries(r.Stacks[0].Outputs.map((o) => [o.OutputKey, o.OutputValue]));
  return cached;
}
