<script lang="ts">
  import { Toaster } from 'svelte-sonner'

  interface Props {
    theme?: 'light' | 'dark'
  }
  let { theme = 'light' }: Props = $props()
</script>

<Toaster
  {theme}
  position="bottom-right"
  closeButton
  duration={4000}
  toastOptions={{
    classes: {
      toast:
        'group !rounded-sm !font-sans !text-sm !bg-white dark:!bg-coolgray-100 !text-black dark:!text-white !border dark:!border-coolgray-200 !border-neutral-200 !shadow-[0_5px_15px_-3px_rgb(0_0_0_/_0.08)]',
      title: '!font-semibold',
      description: '!text-neutral-500 dark:!text-neutral-400',
      success: '!border-l-4 !border-l-green-500 [&_[data-icon]]:!text-green-500',
      error: '!border-l-4 !border-l-red-500 [&_[data-icon]]:!text-red-500',
      warning: '!border-l-4 !border-l-orange-400 [&_[data-icon]]:!text-orange-400',
      info: '!border-l-4 !border-l-blue-500 [&_[data-icon]]:!text-blue-500',
      closeButton:
        '!bg-white dark:!bg-coolgray-100 !border-neutral-200 dark:!border-coolgray-200 !text-neutral-500 hover:!text-black dark:hover:!text-white',
    },
  }}
/>
