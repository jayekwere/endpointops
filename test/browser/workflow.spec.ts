import { test, expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
const tokens = () => JSON.parse(readFileSync('test-results/tokens.json', 'utf8'));
async function connect(page: Page, role: string) {
  await page.getByLabel('Access token', { exact: true }).fill(tokens()[role]);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.locator('#status')).toContainText('demo-' + role);
}
async function capture(page: Page) {
  expect(
    await page
      .locator('[id]')
      .evaluateAll((nodes) => new Set(nodes.map((n) => n.id)).size === nodes.length),
  ).toBe(true);
  await page.getByLabel('Access token', { exact: true }).fill('');
  await page.screenshot({ path: 'test-results/dashboard-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.locator('h1')).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
  await page.screenshot({ path: 'test-results/dashboard-mobile.png', fullPage: true });
  await page.getByRole('button', { name: 'Disconnect', exact: true }).click();
  await expect(page.locator('#status')).toHaveText('Disconnected');
}
test('complete operational workflow and responsive evidence dashboard', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto('/');
  await connect(page, 'operator');
  await expect(page.locator('#failing-count')).toHaveText('1');
  await page.getByRole('button', { name: 'Resolve with readback', exact: true }).click();
  await expect(page.locator('#notice')).toContainText('passing_readback_required');
  await connect(page, 'requester');
  await page.getByRole('button', { name: 'Plan lab firewall repair', exact: true }).click();
  await expect(page.locator('#plans .record')).toHaveCount(1);
  await connect(page, 'reviewer');
  await page.locator('#plans').getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.locator('#plans header .badge')).toHaveText('approved');
  await connect(page, 'operator');
  await page.locator('#plans').getByRole('button', { name: 'Execute', exact: true }).click();
  await expect(page.locator('#failing-count')).toHaveText('0');
  await page.getByRole('button', { name: 'Resolve with readback', exact: true }).click();
  await expect(page.locator('#ticket-count')).toHaveText('0');
  await page.locator('#owner').fill('worker-001');
  await page.getByRole('button', { name: 'Record asset transition', exact: true }).click();
  await expect(page.locator('#devices')).toContainText('assigned');
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export support bundle', exact: true }).click();
  expect((await download).suggestedFilename()).toBe('support-bundle.json');
  await capture(page);
  expect(errors).toEqual([]);
});
test('hostile device labels are rendered as text and enrollment secrets clear on reconnect', async ({
  page,
}) => {
  await page.goto('/');
  await connect(page, 'operator');
  await page.locator('#enroll-id').fill('browser-xss-test');
  await page.locator('#enroll-label').fill('<img src=x onerror=alert(1)>');
  await page.getByRole('button', { name: 'Enroll observation device', exact: true }).click();
  await expect(page.locator('#devices')).toContainText('<img src=x onerror=alert(1)>');
  await expect(page.locator('img')).toHaveCount(0);
  await expect(page.locator('#device-credential')).not.toHaveValue('');
  await connect(page, 'viewer');
  await expect(page.locator('#device-credential')).toHaveValue('');
  await expect(page.locator('#enroll-secret')).toBeHidden();
});
