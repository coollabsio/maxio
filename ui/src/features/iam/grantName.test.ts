import { expect, test } from 'bun:test'
import { folderScopeHint, grantPolicyName, unrestrictedKeyPolicy } from './grantName'

test('grant names include the folder and avoid collisions', () => {
  expect(grantPolicyName(['photos'], 'reports/', 'read', [])).toBe('grant-photos-reports-read')
  expect(grantPolicyName(['photos'], 'reports', 'read', ['grant-photos-reports-read'])).toBe(
    'grant-photos-reports-read-2',
  )
  expect(folderScopeHint(['photos'], 'reports')).toContain('arn:aws:s3:::photos/reports/*')
  expect(folderScopeHint(['photos'], 'reports')).toContain('not reportsX')
  expect(unrestrictedKeyPolicy('Key policy: *')).toBe(true)
  expect(unrestrictedKeyPolicy('Key policy: arn:aws:s3:::photos/uploads/*')).toBe(false)
})
