import { basename } from 'node:path';
import type { FullResult, Reporter, Suite, TestError, TestResult, TestStep } from '@playwright/test/reporter';

type Category = 'microsoft' | 'timeout' | 'assertion';

interface Failure {
  test: string;
  stage: string;
  category: Category;
  error: string;
}

interface Flow {
  flow: string;
  passed: number;
  failed: number;
  skipped: number;
  failures: Failure[];
}

const ansi = new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, 'g');

function clean(text: string): string {
  return text
    .replace(ansi, '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .slice(0, 4)
    .join(' | ')
    .replace(/eyJ[\w-]+\.[\w-]+\.[\w-]*/g, '[token]')
    .replace(/[A-Za-z0-9+/=_.-]{60,}/g, '[redacted]')
    .slice(0, 500);
}

function failedStage(steps: TestStep[], path: string[] = []): string[] | undefined {
  const failing = steps.find((step) => step.error);
  if (!failing) return undefined;
  const next = failing.category === 'test.step' ? [...path, failing.title] : path;
  return failedStage(failing.steps, next) ?? next;
}

function categorize(result: TestResult, message: string): Category {
  if (result.status === 'timedOut') return 'timeout';
  return /AADSTS|Microsoft (reported|sign-in did not finish)|on the Microsoft sign-in page/.test(message)
    ? 'microsoft'
    : 'assertion';
}

export default class SummaryReporter implements Reporter {
  private suite: Suite | undefined;
  private runErrors: string[] = [];

  onBegin(_config: unknown, suite: Suite): void {
    this.suite = suite;
  }

  onError(error: TestError): void {
    this.runErrors.push(clean(error.message ?? error.stack ?? 'Unknown error'));
  }

  async onEnd(result: FullResult): Promise<{ status: 'failed' } | undefined> {
    const tests = this.suite?.allTests() ?? [];
    if (result.status === 'passed' && tests.every((test) => test.results.length === 0)) return undefined;

    const flows = new Map<string, Flow>();

    for (const test of tests) {
      const name = basename(test.location.file)
        .replace(/^\d+-/, '')
        .replace(/\.spec\.ts$/, '');
      const flow = flows.get(name) ?? { flow: name, passed: 0, failed: 0, skipped: 0, failures: [] };
      flows.set(name, flow);

      const outcome = test.outcome();
      if (outcome === 'skipped') {
        flow.skipped++;
      } else if (outcome === 'unexpected') {
        const last = test.results.at(-1);
        const message = clean(last?.errors[0]?.message ?? 'No error message');
        flow.failed++;
        flow.failures.push({
          test: test.title,
          stage: failedStage(last?.steps ?? [])?.join(' > ') || 'outside any step',
          category: last ? categorize(last, message) : 'assertion',
          error: message,
        });
      } else {
        flow.passed++;
      }
    }

    const list = [...flows.values()];
    const sum = (pick: (flow: Flow) => number) => list.reduce((total, flow) => total + pick(flow), 0);
    const passed = sum((flow) => flow.passed);
    const failed = sum((flow) => flow.failed);
    const skipped = sum((flow) => flow.skipped);
    const total = passed + failed + skipped;
    const success = result.status === 'passed' && failed === 0 && this.runErrors.length === 0;

    const width = Math.max(4, ...list.map((flow) => flow.flow.length));
    const lines = ['', 'Results by flow'];
    for (const flow of list) {
      const ok = flow.failed === 0;
      lines.push(
        `  ${flow.flow.padEnd(width)}  ${ok ? 'SUCCESS' : 'FAILED '}  ${flow.passed}/${flow.passed + flow.failed + flow.skipped}`,
      );
      for (const failure of flow.failures) {
        lines.push(
          `    - ${failure.test}`,
          `        stage: ${failure.stage}`,
          `        category: ${failure.category}`,
          `        error: ${failure.error}`,
        );
      }
    }
    for (const error of this.runErrors) lines.push(`  run error: ${error}`);
    lines.push('', `RESULT: ${success ? 'SUCCESS' : 'FAILED'} (${failed} of ${total} tests failed)`, '');
    console.log(lines.join('\n'));

    return success || result.status !== 'passed' ? undefined : { status: 'failed' };
  }
}
