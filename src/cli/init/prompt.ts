// Terminal questions of the init wizard with node:readline/promises (perf 04-REQ-37, NF-06): Ctrl+C
// (SIGINT on the interface) or the end of the input abort the pending question.
import { createInterface } from 'node:readline/promises';
import type { Prompt } from '../host.ts';

/** Thrown by Prompt.ask when the user interrupts the wizard (exit code 130, perf 04-REQ-41). */
export class PromptAborted extends Error {
  constructor() {
    super('interrupted');
    this.name = 'PromptAborted';
  }
}

export function readlinePrompt(
  input: NodeJS.ReadableStream,
  output: NodeJS.WritableStream,
  terminal?: boolean,
): Prompt {
  const rl = createInterface({ input, output, ...(terminal === undefined ? {} : { terminal }) });
  const controller = new AbortController();
  let closed = false;
  rl.on('SIGINT', () => controller.abort());
  rl.on('close', () => {
    closed = true;
    controller.abort();
  });
  return {
    async ask(question) {
      if (controller.signal.aborted) throw new PromptAborted();
      try {
        return await rl.question(question, { signal: controller.signal });
      } catch (error) {
        if (controller.signal.aborted) {
          output.write('\n');
          throw new PromptAborted();
        }
        throw error;
      }
    },
    close() {
      if (!closed) rl.close();
    },
  };
}
