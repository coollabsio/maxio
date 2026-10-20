import { Navigate, Route, Routes } from 'react-router'
import { AppShell } from '@/app/shell/AppShell'
import { RequireAuth } from '@/features/auth/RequireAuth'
import { LoginPage } from '@/features/auth/LoginPage'
import { BucketListPage } from '@/features/buckets/BucketListPage'
import { PoliciesPage } from '@/features/iam/PoliciesPage'
import { PolicyEditorPage } from '@/features/iam/PolicyEditorPage'
import { RequireIamAdmin } from '@/features/iam/RequireIamAdmin'
import { UserDetailPage } from '@/features/iam/UserDetailPage'
import { UsersPage } from '@/features/iam/UsersPage'
import { ObjectBrowserPage } from '@/features/objects/ObjectBrowserPage'
import { BucketSettingsPage } from '@/features/settings/BucketSettingsPage'

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <AppShell />
          </RequireAuth>
        }
      >
        <Route index element={<BucketListPage />} />
        <Route path="buckets/:bucket" element={<ObjectBrowserPage />} />
        <Route path="buckets/:bucket/settings" element={<BucketSettingsPage />} />
        <Route
          path="users"
          element={
            <RequireIamAdmin>
              <UsersPage />
            </RequireIamAdmin>
          }
        />
        <Route
          path="users/:name"
          element={
            <RequireIamAdmin>
              <UserDetailPage />
            </RequireIamAdmin>
          }
        />
        <Route
          path="policies"
          element={
            <RequireIamAdmin>
              <PoliciesPage />
            </RequireIamAdmin>
          }
        />
        <Route
          path="policies/:name"
          element={
            <RequireIamAdmin>
              <PolicyEditorPage />
            </RequireIamAdmin>
          }
        />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
