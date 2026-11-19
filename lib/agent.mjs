// A small client for one conversation with the janitor harness.
// It streams the agent's turn, records every tool call and its result, and
// answers the inline request_human_approval tool by asking an approver.
import { BedrockAgentCoreClient, InvokeHarnessCommand } from '@aws-sdk/client-bedrock-agentcore';
import { randomUUID } from 'node:crypto';
import { region } from './config.mjs';

const client = new BedrockAgentCoreClient({ region });
const APPROVAL_TOOL = 'request_human_approval';

export class Session {
  // approver: async ({ stackName, reason }) => ({ approved: boolean, note?: string })
  // overrides: extra InvokeHarness fields (model, systemPrompt, allowedTools) for experiments
  constructor({ harnessArn, approver, overrides = {}, onEvent = () => {} }) {
    this.harnessArn = harnessArn;
    this.approver = approver;
    this.overrides = overrides;
    this.onEvent = onEvent;
    this.sessionId = `janitor-${randomUUID()}`;
    this.usage = { inputTokens: 0, outputTokens: 0 };
  }

  async send(text) {
    const turn = { text: '', toolCalls: [], stopReasons: [], approvals: [], errors: [] };
    let messages = [{ role: 'user', content: [{ text }] }];

    for (let hop = 0; hop < 8; hop++) {
      const pending = await this.#stream(messages, turn);
      if (pending.length === 0) break;
      // The harness paused on inline tool calls. Answer all of them in one message.
      const content = [];
      for (const call of pending) {
        let result;
        if (call.name === APPROVAL_TOOL) {
          const decision = await this.approver(call.input);
          turn.approvals.push({ ...call.input, ...decision });
          result = decision;
        } else {
          result = { error: `unknown inline tool ${call.name}` };
        }
        call.result = result;
        call.status = 'success';
        content.push({ toolResult: { toolUseId: call.toolUseId, content: [{ text: JSON.stringify(result) }], status: 'success' } });
      }
      messages = [{ role: 'user', content }];
    }
    return turn;
  }

  // Runs one InvokeHarness call. Returns inline tool calls that still need an answer.
  async #stream(messages, turn) {
    const res = await client.send(
      new InvokeHarnessCommand({ harnessArn: this.harnessArn, runtimeSessionId: this.sessionId, messages, ...this.overrides }),
    );
    const blocks = new Map(); // contentBlockIndex -> tool call being assembled
    const byId = new Map(turn.toolCalls.map((c) => [c.toolUseId, c]));
    let resultFor = null;
    let lastStop = null;

    for await (const ev of res.stream) {
      this.onEvent(ev);
      if (ev.messageStart) blocks.clear();
      const start = ev.contentBlockStart?.start;
      if (start?.toolUse) {
        const call = { toolUseId: start.toolUse.toolUseId, name: start.toolUse.name, inputJson: '', input: null, status: null, result: null };
        blocks.set(ev.contentBlockStart.contentBlockIndex, call);
        byId.set(call.toolUseId, call);
        turn.toolCalls.push(call);
      }
      if (start?.toolResult) {
        resultFor = byId.get(start.toolResult.toolUseId) ?? null;
        if (resultFor) {
          resultFor.status = start.toolResult.status;
          resultFor.resultText = '';
        }
      }
      const delta = ev.contentBlockDelta?.delta;
      if (delta?.text) turn.text += delta.text;
      if (delta?.toolUse?.input) {
        const call = blocks.get(ev.contentBlockDelta.contentBlockIndex);
        if (call) call.inputJson += delta.toolUse.input;
      }
      if (delta?.toolResult && resultFor) for (const part of delta.toolResult) resultFor.resultText += part.text ?? '';
      if (ev.contentBlockStop) {
        const call = blocks.get(ev.contentBlockStop.contentBlockIndex);
        if (call && call.input === null) call.input = safeJson(call.inputJson) ?? {};
        if (resultFor?.resultText !== undefined && resultFor.result === null) resultFor.result = safeJson(resultFor.resultText) ?? resultFor.resultText;
      }
      if (ev.messageStop) {
        lastStop = ev.messageStop.stopReason;
        turn.stopReasons.push(lastStop);
      }
      if (ev.metadata?.usage) {
        this.usage.inputTokens += ev.metadata.usage.inputTokens ?? 0;
        this.usage.outputTokens += ev.metadata.usage.outputTokens ?? 0;
      }
      for (const k of ['runtimeClientError', 'validationException', 'internalServerException'])
        if (ev[k]) turn.errors.push(`${k}: ${ev[k].message}`);
    }
    if (lastStop !== 'tool_use') return [];
    return turn.toolCalls.filter((c) => c.status === null);
  }
}

function safeJson(s) {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

// "janitor___delete_stack" -> "delete_stack"
export const shortName = (n) => (n.includes('___') ? n.slice(n.indexOf('___') + 3) : n);
