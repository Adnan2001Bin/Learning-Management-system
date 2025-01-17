import { useState } from 'react'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'
import { Button } from './components/ui/button'
import { createBrowserRouter, RouterProvider } from 'react-router'
import AuthPage from './pages/auth'

function App() {
  const router = createBrowserRouter([
    {
      path:"/auth",
      element:(
        <AuthPage />
      )
    }
  ])

  return (
    <div>
      <RouterProvider router={router}/>
    </div>
  )
}

export default App
