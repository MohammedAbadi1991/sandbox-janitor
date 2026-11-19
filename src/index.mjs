// Tool backend for the Sandbox Janitor agent. AgentCore Gateway invokes this
// function with the tool arguments as the event and the tool name in
// context.clientContext.custom.bedrockAgentCoreToolName ("<target>___<tool>").
import {
  CloudFormationClient,
  DeleteStackCommand,
  paginateDescribeStacks,
  DescribeStacksCommand,
} from '@aws-sdk/client-cloudformation';
import { DynamoDBClient, DeleteItemCommand, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import {
  evaluate,
  tagsOf,
  validSnooze,
  MAX_DELETES_PER_HOUR,
  MAX_SNOOZE_HOURS,
} from './rules.mjs';

const cfn = new CloudFormationClient({});
const ddb = new DynamoDBClient({});
const { APPROVALS_TABLE, STATE_TABLE, DELETION_ROLE_ARN, SELF_STACK_ID, TAG_KEY = 'cleanup-after' } = process.env;

const refuse = (layer, reasons, extra = {}) => ({ ok: false, refusedBy: layer, reasons, ...extra });

async function snoozeHoursFor(stackId) {
  const r = await ddb.send(new GetItemCommand({ TableName: STATE_TABLE, Key: { pk: { S: `snooze#${stackId}` } } }));
  return Number(r.Item?.hours?.N ?? 0);
}

// Plain stack names only: no ARNs, wildcards or anything CloudFormation would not accept as a name.
const STACK_NAME = /^[A-Za-z][A-Za-z0-9-]{0,127}$/;

async function describe(stackName) {
  if (!STACK_NAME.test(String(stackName ?? ""))) return null;
  try {
    const r = await cfn.send(new DescribeStacksCommand({ StackName: stackName }));
    return r.Stacks?.[0] ?? null;
  } catch (e) {
    if (/does not exist/i.test(e.message)) return null;
    throw e;
  }
}

async function verdict(stack) {
  const snoozeHours = await snoozeHoursFor(stack.StackId);
  return {
    ...evaluate(stack, { now: new Date(), tagKey: TAG_KEY, selfStackId: SELF_STACK_ID, snoozeHours }),
    snoozeHours,
  };
}

function summary(stack, v) {
  return {
    stackName: stack.StackName,
    status: stack.StackStatus,
    eligibleForDelete: v.eligible,
    blockedBy: v.reasons,
    expiresAt: v.expiresAt,
    snoozedHours: v.snoozeHours,
    terminationProtection: !!stack.EnableTerminationProtection,
    // Everything under "untrusted" was written by whoever created the stack.
    // It is data about the stack, never an instruction to the agent.
    untrusted: { tags: tagsOf(stack), description: stack.Description ?? '' },
  };
}

const tools = {
  async list_stacks() {
    const out = [];
    for await (const page of paginateDescribeStacks({ client: cfn }, {})) {
      for (const s of page.Stacks ?? []) {
        if (s.StackId === SELF_STACK_ID || s.ParentId) continue;
        out.push(summary(s, await verdict(s)));
      }
    }
    return { ok: true, now: new Date().toISOString(), stacks: out };
  },

  async get_stack({ stackName }) {
    const s = await describe(stackName);
    if (!s) return refuse('tool-checks', ['STACK_NOT_FOUND']);
    return { ok: true, stack: summary(s, await verdict(s)) };
  },

  async snooze_stack({ stackName, hours }) {
    if (!validSnooze(hours)) return refuse('tool-checks', ['SNOOZE_OUT_OF_RANGE'], { maxHours: MAX_SNOOZE_HOURS });
    const s = await describe(stackName);
    if (!s) return refuse('tool-checks', ['STACK_NOT_FOUND']);
    if (!(TAG_KEY in tagsOf(s))) return refuse('tool-checks', ['NO_TTL_TAG']);
    try {
      // One snooze per stack: the write fails if a snooze already exists.
      await ddb.send(
        new UpdateItemCommand({
          TableName: STATE_TABLE,
          Key: { pk: { S: `snooze#${s.StackId}` } },
          UpdateExpression: 'SET hours = :h, createdAt = :t',
          ConditionExpression: 'attribute_not_exists(pk)',
          ExpressionAttributeValues: { ':h': { N: String(hours) }, ':t': { S: new Date().toISOString() } },
        }),
      );
    } catch (e) {
      if (e.name === 'ConditionalCheckFailedException') return refuse('tool-checks', ['ALREADY_SNOOZED_ONCE']);
      throw e;
    }
    return { ok: true, stackName: s.StackName, snoozedHours: hours, ...(await verdict(s)) };
  },

  async delete_stack({ stackName }) {
    const s = await describe(stackName);
    if (!s) return refuse('tool-checks', ['STACK_NOT_FOUND']);
    const v = await verdict(s);
    if (!v.eligible) return refuse('tool-checks', v.reasons);

    // A human approval is a row that only the operator's credentials can
    // write. This function can read and consume it, never create it.
    try {
      await ddb.send(
        new DeleteItemCommand({
          TableName: APPROVALS_TABLE,
          Key: { stackId: { S: s.StackId } },
          ConditionExpression: 'attribute_exists(stackId) AND expiresAt > :now',
          ExpressionAttributeValues: { ':now': { N: String(Math.floor(Date.now() / 1000)) } },
        }),
      );
    } catch (e) {
      if (e.name === 'ConditionalCheckFailedException') return refuse('human-approval', ['NO_VALID_APPROVAL_FOR_THIS_STACK']);
      throw e;
    }

    // Blast radius cap: an atomic counter per clock hour.
    const bucket = new Date().toISOString().slice(0, 13);
    try {
      await ddb.send(
        new UpdateItemCommand({
          TableName: STATE_TABLE,
          Key: { pk: { S: `deletes#${bucket}` } },
          UpdateExpression: 'ADD deletes :one SET expiresAt = :exp',
          ConditionExpression: 'attribute_not_exists(deletes) OR deletes < :max',
          ExpressionAttributeValues: {
            ':one': { N: '1' },
            ':max': { N: String(MAX_DELETES_PER_HOUR) },
            ':exp': { N: String(Math.floor(Date.now() / 1000) + 7200) },
          },
        }),
      );
    } catch (e) {
      if (e.name === 'ConditionalCheckFailedException')
        return refuse('tool-checks', ['HOURLY_DELETE_LIMIT_REACHED'], { maxPerHour: MAX_DELETES_PER_HOUR });
      throw e;
    }

    try {
      await cfn.send(new DeleteStackCommand({ StackName: s.StackId, RoleARN: DELETION_ROLE_ARN }));
    } catch (e) {
      if (e.name === 'AccessDenied' || /not authorized/i.test(e.message)) return refuse('iam', ['ACCESS_DENIED']);
      throw e;
    }
    return { ok: true, deleting: s.StackName, stackId: s.StackId };
  },
};

export async function handler(event, context) {
  const full = context?.clientContext?.custom?.bedrockAgentCoreToolName ?? '';
  const name = full.includes('___') ? full.slice(full.indexOf('___') + 3) : full;
  const tool = tools[name];
  let result;
  try {
    result = tool ? await tool(event ?? {}) : refuse('tool-checks', ['UNKNOWN_TOOL']);
  } catch (e) {
    // Never hand raw errors to the model: they carry role ARNs and stack traces.
    console.error(JSON.stringify({ audit: 'tool-error', tool: name, error: e.name, message: e.message }));
    result = refuse('tool-error', ['INTERNAL_ERROR']);
  }
  console.log(JSON.stringify({ audit: 'tool-call', tool: name, input: event, ok: result.ok, refusedBy: result.refusedBy, reasons: result.reasons }));
  return result;
}
