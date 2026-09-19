#!/usr/bin/env node

import { createCli } from '../dist/cli.js';

const program = createCli();
program.parse(process.argv);
