// lib/auth.ts - Debug version
import { NextAuthOptions } from 'next-auth';
import KeycloakProvider from 'next-auth/providers/keycloak';

// Add console logs to debug
console.log('NextAuth Config:', {
  KEYCLOAK_CLIENT_ID: process.env.KEYCLOAK_CLIENT_ID,
  KEYCLOAK_ISSUER: process.env.KEYCLOAK_ISSUER,
  NEXTAUTH_URL: process.env.NEXTAUTH_URL,
  hasClientSecret: !!process.env.KEYCLOAK_CLIENT_SECRET,
});

declare module 'next-auth' {
  interface Session {
    accessToken: string;
    refreshToken: string;
    idToken: string;
  }
}

export const authOptions: NextAuthOptions = {
  debug: true, // Enable debug mode
  providers: [
    KeycloakProvider({
      clientId: process.env.KEYCLOAK_CLIENT_ID!,
      clientSecret: process.env.KEYCLOAK_CLIENT_SECRET!,
      issuer: process.env.KEYCLOAK_ISSUER!,
      authorization: {
        params: {
          scope: 'openid email profile',
        },
      },
    }),
  ],
  callbacks: {
    async jwt({ token, account }) {
      console.log('JWT Callback:', { token, account });
      if (account) {
        token.accessToken = account.access_token;
        token.refreshToken = account.refresh_token;
        token.idToken = account.id_token;
      }
      return token;
    },
    async session({ session, token }) {
      console.log('Session Callback:', { session, token });
      session.accessToken = token.accessToken as string;
      session.refreshToken = token.refreshToken as string;
      session.idToken = token.idToken as string;
      return session;
    },
    async signIn({ account, profile }) {
      console.log('SignIn Callback:', { account, profile });
      return true;
    },
  },
  events: {
    async signIn(message) {
      console.log('SignIn Event:', message);
    },
    async signOut(message) {
      console.log('SignOut Event:', message);
    },
    async createUser(message) {
      console.log('CreateUser Event:', message);
    },
    async session(message) {
      console.log('Session Event:', message);
    },
  },
  pages: {
    signIn: '/auth/signin',
    error: '/auth/error',
  },
  session: {
    strategy: 'jwt',
  },
};