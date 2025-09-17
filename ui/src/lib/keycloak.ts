// lib/keycloak.ts - Keycloak utilities
export interface KeycloakConfig {
  url: string;
  realm: string;
  clientId: string;
}

export const keycloakConfig: KeycloakConfig = {
  url: process.env.NEXT_PUBLIC_KEYCLOAK_URL || 'https://your-keycloak-domain',
  realm: process.env.NEXT_PUBLIC_KEYCLOAK_REALM || 'your-realm',
  clientId: process.env.NEXT_PUBLIC_KEYCLOAK_CLIENT_ID || 'your-client-id',
};

export const getKeycloakLogoutUrl = (redirectUri?: string) => {
  const logoutUrl = new URL(`${keycloakConfig.url}/auth/realms/${keycloakConfig.realm}/protocol/openid-connect/logout`);
  if (redirectUri) {
    logoutUrl.searchParams.set('redirect_uri', redirectUri);
  }
  return logoutUrl.toString();
};