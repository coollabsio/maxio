import { Toaster as Sonner, type ToasterProps } from 'sonner'

function Toaster({ theme = 'light', ...props }: ToasterProps) {
  return (
    <Sonner
      theme={theme}
      position="bottom-right"
      closeButton
      duration={4000}
      toastOptions={{
        classNames: {
          toast:
            'group !rounded-lg !font-sans !text-[13px] !bg-white dark:!bg-coolgray-200 !text-black dark:!text-fg !border dark:!border-white/[0.08] !border-neutral-200 !shadow-dropdown',
          title: '!font-semibold',
          description: '!text-neutral-500 dark:!text-neutral-400',
          success: '[&_[data-icon]]:!text-green-500',
          error: '[&_[data-icon]]:!text-red-500',
          warning: '[&_[data-icon]]:!text-orange-400',
          info: '[&_[data-icon]]:!text-blue-500',
          closeButton:
            '!bg-white dark:!bg-coolgray-200 !border-neutral-200 dark:!border-white/[0.08] !text-neutral-500 hover:!text-black dark:hover:!text-white',
        },
      }}
      {...props}
    />
  )
}

export { Toaster }
