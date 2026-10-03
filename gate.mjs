// Public generic code. This module accepts no private contents or credentials.
export const REPOSITORY = 'RoniSaroniemi/foxie-verification-carrier';
export const REPOSITORY_ID = 1402558215;
export const WORKFLOW = '.github/workflows/digest-approval.yml';
export const PREDICATE_TYPE = 'https://github.com/RoniSaroniemi/foxie-verification-carrier/digest-approval/v1';
export const SUBJECT = 'sealed-manifest';
export const ENVIRONMENTS = Object.freeze({ 'journal-admission': 'digest-journal-admission', publication: 'digest-publication' });
const check = (condition, code) => { if (!condition) throw new Error(code); };
export function classifiedInput(input) {
  check(input && Object.keys(input).sort().join('|') === 'manifest_digest|stage', 'DIGEST_INPUT_FIELDS');
  check(Object.hasOwn(ENVIRONMENTS, input.stage) && /^sha256:[0-9a-f]{64}$/.test(input.manifest_digest), 'DIGEST_INPUT_INVALID');
  return { stage: input.stage, manifestDigest: input.manifest_digest };
}
export function approvalComment(input, runId, runAttempt) {
  const value = classifiedInput(input);
  check(Number.isSafeInteger(runId) && runId > 0 && Number.isSafeInteger(runAttempt) && runAttempt > 0, 'DIGEST_RUN_INVALID');
  return 'DIGEST-APPROVAL/v1\n' + JSON.stringify({ ...value, runId, runAttempt });
}
export function approvedPredicate(input, context, environment, policies, reviews) {
  const value = classifiedInput(input);
  check(context.repo === REPOSITORY && context.repositoryId === REPOSITORY_ID && context.ref === 'refs/heads/main' &&
    context.event === 'workflow_dispatch' && context.actorId === 32576196 && /^[0-9a-f]{40}$/.test(context.sha), 'DIGEST_CARRIER_INVALID');
  check(environment.name === ENVIRONMENTS[value.stage] && Number.isSafeInteger(environment.id) && environment.id > 0 &&
    environment.deployment_branch_policy?.custom_branch_policies === true &&
    environment.deployment_branch_policy?.protected_branches === false, 'DIGEST_PROTECTION_INVALID');
  const rules = environment.protection_rules?.filter(rule => rule.type === 'required_reviewers');
  check(rules?.length === 1 && rules[0].prevent_self_review === false && rules[0].reviewers?.length === 1 &&
    rules[0].reviewers[0].type === 'User' && rules[0].reviewers[0].reviewer?.id === 32576196, 'DIGEST_REVIEWER_INVALID');
  check(policies.total_count === 1 && policies.branch_policies?.length === 1 &&
    policies.branch_policies[0].name === 'main' && policies.branch_policies[0].type === 'branch', 'DIGEST_BRANCH_INVALID');
  const relevant = reviews.filter(review => review.environments?.some(item => item.id === environment.id && item.name === environment.name));
  check(relevant.length === 1 && relevant[0].state === 'approved' && relevant[0].user?.type === 'User' &&
    relevant[0].user.id === 32576196 && relevant[0].comment === approvalComment(input, context.runId, context.runAttempt), 'DIGEST_APPROVAL_INVALID');
  // Every value below is public generic stage/digest or native carrier identity.
  return { version: 1, ...value, repositoryId: REPOSITORY_ID, workflow: WORKFLOW, carrierSha: context.sha,
    runId: context.runId, runAttempt: context.runAttempt, environmentId: environment.id, reviewerId: 32576196 };
}
