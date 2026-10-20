// Exercise the shipped dashboard mixin without a network or DOM framework.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('zscope/web/static/dashboard_reports.js', 'utf8');
let fetchHandler;
const context = vm.createContext({window: {}, encodeURIComponent,
  fetch: (...args) => fetchHandler(...args),
  ZScopeReport: {mount: () => ({toc: []})},
});
vm.runInContext(source, context);
const notices = [];
const app = {...context.window.ZScopeDashboardReports, businessDrafts: {},
  $nextTick: async () => {}, $refs: {markdownReport: {}, reportScroll: {}},
  resetFindingValidationBaseline: () => {}, showToast: (...args) => notices.push(args),
};
function envelope(id, base = 'base', answer = 'unknown', revision = 0) {
  return {report_id: 'report', issue_id: id, base_revision: base, available: true,
    revalidation_required: revision > 0,
    questions: [{id: `q-${id}`, subject_key: `s-${id}`, statement: id,
      answer, source_note: answer === 'yes' ? 'spec' : '', expected_revision: revision}]};
}
function page(review) { return {markdown: 'report', review: {validation_status: 'needs_review', user_rebuttal: ''}, business_review: review}; }
function response(data, ok = true) { return {ok, json: async () => data}; }
async function load(id, review = envelope(id)) {
  fetchHandler = async () => response(page(review));
  app.selectedFinding = {issue_id: id};
  await app.loadMarkdownReport(app.selectedFinding);
}
(async () => {
  await load('A');
  app.businessReview.questions[0].answer = 'yes';
  app.businessReview.questions[0].source_note = 'spec';
  await load('B');
  assert.equal(app.businessReview.issue_id, 'B');
  await load('A');
  assert.equal(app.businessReview.questions[0].answer, 'yes');
  let finishSave;
  fetchHandler = async (_url, options) => {
    const body = JSON.parse(options.body);
    assert.deepEqual(Object.keys(body).sort(), ['answers', 'base_revision', 'issue_id', 'report_id']);
    assert.equal(body.answers.length, 1);
    return await new Promise(resolve => { finishSave = resolve; });
  };
  const saving = app.saveBusinessReview();
  await load('B');
  finishSave(response({success: true, business_review: envelope('A', 'base', 'yes', 1)}));
  await saving;
  assert.equal(app.businessReview.issue_id, 'B', 'late save must not change the selected issue');
  assert.equal(app.businessDrafts['report:A'].questions[0].expected_revision, 1);
  await load('A', envelope('A', 'base', 'yes', 1));
  app.businessReview.questions[0].answer = 'no';
  app.businessReview.questions[0].source_note = 'new agreement';
  await load('A', envelope('A', 'changed evidence', 'yes', 1));
  assert.equal(app.businessReview.stale, true);
  fetchHandler = () => { throw new Error('stale draft must not be submitted'); };
  await app.saveBusinessReview();
  assert.equal(app.businessReview.questions[0].source_note, 'new agreement');
  fetchHandler = async () => response(page(envelope('A', 'changed evidence', 'yes', 1)));
  await app.reloadBusinessReview();
  assert.equal(app.businessReview.base_revision, 'changed evidence');
  app.businessReview.questions[0].answer = 'no';
  fetchHandler = async () => response({error: 'revision conflict'}, false);
  await app.saveBusinessReview();
  assert.equal(app.businessReview.questions[0].answer, 'no', 'failed saves retain the draft');
  assert.equal(notices.at(-1)[0], 'revision conflict');
  let finishOld;
  fetchHandler = async () => await new Promise(resolve => { finishOld = resolve; });
  const older = app.loadMarkdownReport({issue_id: 'old'});
  await load('latest');
  finishOld(response(page(envelope('old'))));
  await older;
  assert.equal(app.businessReview.issue_id, 'latest', 'late fetch must not overwrite the selection');
  console.log('business review UI: drafts, stale evidence, conflicts and response races passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
