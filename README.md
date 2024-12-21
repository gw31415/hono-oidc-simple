# @gw31415/hono-oidc-simple
[![npm version](https://badge.fury.io/js/@gw31415%2Fhono-oidc-simple.svg?icon=si%3Anpm)](https://badge.fury.io/js/@gw31415%2Fhono-oidc-simple)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

`@gw31415/hono-oidc-simple` simplifies the implementation of OpenID Connect
(OIDC) authentication in Hono-based applications. It provides tools for managing
tokens, user sessions, and handling login and logout easily.

---

## Features

- Zero Dependency: No `dependencies` in `package.json`. Only `devDependencies` or
  `peerDependencies` (`hono`) are used.
- Middleware Creation: Provides middleware and handlers for managing user
  authentication states.
- Customizable: Abstract methods allow flexibility in how tokens are stored or
  retrieved.
- Multi-Runtime Support: Works with below runtimes:
  - [x] Bun
  - [x] Cloudflare Workers
  - [x] Deno
  - [x] Node.js

## Installation

```bash
npm i @gw31415/hono-oidc-simple
```

## Usage


### Setup and Create Middleware of OIDC

```ts
/** Cookie expiration period */
const COOKIE_MAXAGE = 60 * 60 * 24 * 30 * 6; // 6 months

/** Set-up OIDC */
const oidc = OIDC((c) => {
  const envs = env<{
    OIDC_GOOGLE_CLIENT: string;
    OIDC_GOOGLE_SECRET: string;
  }>(c);
  return {
    issuers: [
      {
        issuer: "https://accounts.google.com",
        authEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
        tokenEndpoint: "https://oauth2.googleapis.com/token",
        tokenRevocationEndpoint: "https://oauth2.googleapis.com/revoke",
        useLocalJwt: false,
        createClaims: async (c, tokens) => {
          const idToken: string | undefined = await token.getIDToken(c);
          if (idToken) {
            const jwks = createRemoteJWKSet(
              new URL("https://www.googleapis.com/oauth2/v3/certs"),
            );
            try
            {
              const { payload } = await jwtVerify(idToken, jwks, {
                issuer: "https://accounts.google.com",
                audience: envs.OIDC_GOOGLE_CLIENT,
              });
              return payload as Claims;
            } catch (e) {
              console.error(e);
            }
          }
          return undefined;
        },
        scopes: ["openid", "email", "profile"],
        client_id: envs.OIDC_GOOGLE_CLIENT,
        client_secret: envs.OIDC_GOOGLE_SECRET,
      },
    ],
    getIssUrl: () => "https://accounts.google.com",
    clientSideTokenStore: {
      getRefreshToken: (c) => getCookie(c, "refresh_token"),
      getIDToken: (c) => getCookie(c, "jwt"),
      setRefreshToken: (c, token) => {
        if (!token) {
          deleteCookie(c, "refresh_token");
          return;
        }
        const reqUrl = new URL(c.req.url);
        const opts: CookieOptions = {
          path: "/",
          sameSite: "Lax",
          httpOnly: true,
          secure: reqUrl.hostname !== "localhost",
          maxAge: COOKIE_MAXAGE,
        };
        setCookie(c, "refresh_token", token, opts);
      },
      setIDToken: (c, token) => {
        if (!token) {
          deleteCookie(c, "jwt");
          return;
        }
        const reqUrl = new URL(c.req.url);
        const secure = reqUrl.hostname !== "localhost";
        return setCookie(c, "jwt", token, {
          path: "/",
          sameSite: "Lax",
          httpOnly: true,
          secure,
          maxAge: COOKIE_MAXAGE,
        });
      },
    },
  };
});
```

### Create your Middlewares to get the claims

```ts
type Middleware = OIDCMiddlewareType<typeof oidc>;

/**
 * @param iss OIDC Issuer URL
 */
export const loginRoute = (iss: IssuerType<typeof oidc>) =>
  createRoute(
    oidc.loginHandler(iss, (res, c) => {
      if (res.type === "ERR") {
        const error = res.error;
        switch (error) {
          case "Unauthorized":
            return c.redirect("/");
          case "OAuthServerError":
            return c.text(`Error: ${error}`, { status: 500 });
          default:
            return c.text("Invalid state", { status: 500 });
        }
      }
      return c.redirect("/");
    }),
  );

export const logoutRoute = createRoute(
  oidc.logoutHandler((c) => {
    return c.redirect("/");
  }),
);

export const useClaims = oidc.useClaims;

/** Middleware to specify pages that require login */
export const loginRequired: Middleware = every(useClaims, (async (c, next) => {
  if (!c.var.claims) {
    return c.render(
      <div className="font-sans size-full flex items-center justify-center">
        <Card>
          <CardHeader>
            <CardTitle>Protected Page</CardTitle>
          </CardHeader>
          <CardContent>
            <CardDescription>
	            You must be logged in to view this page.
            </CardDescription>
          </CardContent>
          <CardFooter>
            <Button asChild className="w-full">
              <a href="/login">Login</a>
            </Button>
          </CardFooter>
        </Card>
      </div>,
      { title: "Login Required" },
    );
  }
  return await next();
}) satisfies Middleware);
```

## License

Apache-2.0
