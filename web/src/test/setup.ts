// Adds DOM matchers such as toBeInTheDocument() to Vitest's expect, and unmounts components
// between tests so they can't leak into each other.
import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

afterEach(() => cleanup())
