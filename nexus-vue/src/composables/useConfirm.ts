import { ref, shallowRef } from 'vue'

export interface ConfirmOptions {
  title?:       string
  message:      string
  confirmText?: string
  cancelText?:  string
  destructive?: boolean
}

const visible = ref(false)
const opts    = shallowRef<ConfirmOptions>({ message: '' })
let _resolve: (v: boolean) => void = () => {}

export function useConfirm() {
  function confirm(options: ConfirmOptions | string): Promise<boolean> {
    opts.value    = typeof options === 'string' ? { message: options } : options
    visible.value = true
    return new Promise<boolean>(resolve => { _resolve = resolve })
  }

  function _confirm() { visible.value = false; _resolve(true)  }
  function _cancel()  { visible.value = false; _resolve(false) }

  return { visible, opts, confirm, _confirm, _cancel }
}