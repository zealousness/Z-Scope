// Local artifact verification; uses no product API and never starts a scan.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const {chromium} = require(process.env.ZSCOPE_UI_PLAYWRIGHT_MODULE || 'playwright');
(async () => {
  const browser = await chromium.launch({headless: true, executablePath: process.env.ZSCOPE_UI_CHROMIUM});
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}});
  const errors = [], external = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', route => {
    if (/^https?:/.test(route.request().url())) { external.push(route.request().url()); return route.abort(); }
    return route.continue();
  });
  try {
    await page.goto(pathToFileURL(path.join(__dirname, 'primitives.html')).href);
    for (const width of [1440, 390, 1280, 1920]) {
      await page.setViewportSize({width, height: 1000});
      for (const flow of ['first-primitives', 'discover-review', 'interface-update']) {
        await page.locator(`[data-flow="${flow}"]`).click();
        await page.locator('#width').selectOption(width === 390 ? '390' : '1440');
        await page.waitForFunction(() => [...document.querySelectorAll('.comparison img')].every(img => img.complete && img.naturalWidth > 0));
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1), false);
      }
    }
    await page.locator('#after').click();
    assert.equal(await page.locator('#zoom').evaluate(el => el.open), true);
    await page.keyboard.press('Escape');
    await page.getByLabel('一级导航与连续引导选择').selectOption('采用新版');
    await page.getByLabel('一级导航与连续引导意见').fill('保留引导');
    await page.reload();
    assert.equal(await page.getByLabel('一级导航与连续引导选择').inputValue(), '采用新版');
    const download = page.waitForEvent('download');
    await page.locator('#export').click();
    const data = JSON.parse(fs.readFileSync(await (await download).path(), 'utf8'));
    assert.equal(data.choices.length, 5);
    assert.equal(data.choices[0].choice, '采用新版');
    assert.equal(data.choices[1].choice, '继续调整');
    assert.equal(data.automatic_product_changes, false);
    assert.deepEqual(errors, []);
    assert.deepEqual(external, []);
    console.log('Comparison: 12 layout/flow combinations, images, zoom, persistence and export passed; no external requests.');
  } finally { await browser.close(); }
})().catch(error => {console.error(error); process.exitCode = 1;});
