export function AppVersion({ version }: { version: string }) {
  return (
    <span className="text-[11px] font-medium tabular-nums text-neutral-400 dark:text-fg-faint">
      v{version}
    </span>
  )
}
