#!/usr/bin/env node
// Binary "pw-sec" (11-REQ-01): the setup wizard.
import { main, nodeHost } from '../cli/index.ts';

process.exitCode = await main(process.argv.slice(2), nodeHost());
