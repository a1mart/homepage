// middleware.ts - Route protection
import { withAuth } from 'next-auth/middleware';

export default withAuth(
  function middleware(req) {
    console.log('User authenticated:', req.nextauth.token?.email);
  },
  {
    callbacks: {
      authorized: ({ token, req }) => {
        if (req.nextUrl.pathname.startsWith('/dashboard') || 
            req.nextUrl.pathname.startsWith('/api/k8s-cluster-data')) {
          return !!token;
        }
        return true;
      },
    },
  }
);

export const config = {
  matcher: ['/dashboard/:path*', '/api/k8s-cluster-data/:path*'],
};