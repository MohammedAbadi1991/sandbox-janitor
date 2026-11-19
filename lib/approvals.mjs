// Human approval. An approval is one DynamoDB row keyed by the stack's full
// ID, valid for five minutes and consumed by the first delete. It is written
// with the OPERATOR's credentials: neither the model nor the tool function's
// role is able to create one.
import { CloudFormationClient, DescribeStacksCommand } from '@aws-sdk/client-cloudformation';
import { DynamoDBClient, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { region } from './config.mjs';

const cfn = new CloudFormationClient({ region });
const ddb = new DynamoDBClient({ region });

// What the operator is shown comes from CloudFormation, not from the agent.
export async function stackFacts(stackName) {
  try {
    const s = (await cfn.send(new DescribeStacksCommand({ StackName: stackName }))).Stacks[0];
    return {
      stackName: s.StackName,
      stackId: s.StackId,
      status: s.StackStatus,
      created: s.CreationTime?.toISOString(),
      updated: s.LastUpdatedTime?.toISOString() ?? null,
      terminationProtection: !!s.EnableTerminationProtection,
      tags: Object.fromEntries((s.Tags ?? []).map((t) => [t.Key, t.Value])),
    };
  } catch {
    return null;
  }
}

export async function recordApproval(table, stackId, approvedBy) {
  await ddb.send(
    new PutItemCommand({
      TableName: table,
      Item: {
        stackId: { S: stackId },
        approvedBy: { S: approvedBy },
        approvedAt: { S: new Date().toISOString() },
        expiresAt: { N: String(Math.floor(Date.now() / 1000) + 300) },
      },
    }),
  );
}
