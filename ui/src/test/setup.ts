import '@happy-dom/global-registrator/register.js'
import { afterEach } from 'bun:test'
import { cleanup } from '@testing-library/react'

;(window as unknown as { happyDOM: { setURL: (url: string) => void } }).happyDOM.setURL('http://localhost/')

afterEach(() => cleanup())
