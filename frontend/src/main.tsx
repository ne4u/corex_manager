import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import App from './App'
import { queryClient } from './lib/queryClient'
import { ThemeProvider } from './themes/ThemeProvider'
import { LanguageProvider } from './contexts/LanguageContext'
import { DateTimeProvider } from './contexts/DateTimeContext'
import './i18n/config'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ThemeProvider>
      <LanguageProvider>
        <DateTimeProvider>
          <QueryClientProvider client={queryClient}>
            <BrowserRouter>
              <App />
            </BrowserRouter>
          </QueryClientProvider>
        </DateTimeProvider>
      </LanguageProvider>
    </ThemeProvider>
  </React.StrictMode>,
)
