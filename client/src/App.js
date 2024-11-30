import React from 'react';
import { createBrowserRouter, RouterProvider } from 'react-router-dom';

/** import all components */
import Username from './components/Username';
import Password from './components/Password';
import Register from './components/Register';
import Profile from './components/Profile';
import Recovery from './components/Recovery';
import Reset from './components/Reset';
import PageNotFound from './components/PageNotFound';

import { AuthorizedUser,ProtectRoute } from './middleware/auth';


const router = createBrowserRouter([
    {
        path : '/',
        element : <Username></Username>
    },
    {
        path : '/register',
        element : <Register></Register>
    },
    {
        path : '/password',
        element : <ProtectRoute>
             <Password />
        </ProtectRoute>
       
    },
    {
        path : '/profile',
        element : <AuthorizedUser>
                <Profile />
            </AuthorizedUser>
    },
    {
        path : '/recovery',
        element : <Recovery></Recovery>
    },
    {
        path : '/reset',
        element : <Reset></Reset>
    },
    {
        path : '*',
        element : <PageNotFound></PageNotFound>
    },
])

function App() {
  return (
    <main>
        
      <RouterProvider router={router}></RouterProvider>
      
    </main>
  );
}

export default App;
