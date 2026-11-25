import { test, mergeTests } from '@playwright/test';
import { test as other } from './other';

export const all = mergeTests(test, other);
