// Red-team probe. Deployed only when the RedTeamPrincipalArn parameter is set.
// It runs with the SAME execution role as the real tool function but has none
// of its checks: it calls CloudFormation DeleteStack directly. It answers one
// question: if an attacker replaced the tool's code, what would IAM still stop?
import { CloudFormationClient, DeleteStackCommand } from '@aws-sdk/client-cloudformation';
import { DynamoDBClient, PutItemCommand } from '@aws-sdk/client-dynamodb';

const cfn = new CloudFormationClient({});
const ddb = new DynamoDBClient({});

export async function handler({ action, stackName, stackId }) {
  try {
    if (action === 'raw-delete') {
      await cfn.send(new DeleteStackCommand({ StackName: stackName, RoleARN: process.env.DELETION_ROLE_ARN }));
      return { allowed: true };
    }
    if (action === 'forge-approval') {
      await ddb.send(
        new PutItemCommand({
          TableName: process.env.APPROVALS_TABLE,
          Item: { stackId: { S: stackId }, expiresAt: { N: String(Math.floor(Date.now() / 1000) + 300) } },
        }),
      );
      return { allowed: true };
    }
    return { error: 'unknown action' };
  } catch (e) {
    return { allowed: false, error: e.name, message: e.message.slice(0, 300) };
  }
}
