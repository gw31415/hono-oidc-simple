# @gw31415/hono-oidc-simple

`@gw31415/hono-oidc-simple` simplifies the implementation of OpenID Connect
(OIDC) authentication in Hono-based applications. It provides tools for managing
tokens, user sessions, and handling login and logout easily.

---

## Features

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

### Define Your Oidc Implementation

You need to extend the abstract Oidc class and implement methods to retrieve and
store tokens.

```ts
import {
  Oidc as AbstractOidc,
  type IssuerMetadata,
  type MayIssuer,
} from "@gw31415/hono-oidc-simple";
import type { Context } from "hono";
import { env } from "hono/adapter";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { CookieOptions } from "hono/utils/cookie";
import {
  type JWTPayload,
  createRemoteJWKSet,
  decodeJwt,
  jwtVerify,
} from "jose";

const COOKIE_MAXAGE = 60 * 60 * 24 * 30 * 6; // 6 months

class Oidc extends AbstractOidc<"https://accounts.google.com", JWTPayload> {
  async getIssuerMetadata(
    c: Context,
    iss: MayIssuer<"https://accounts.google.com">,
  ): Promise<IssuerMetadata<"https://accounts.google.com"> | undefined> {
    if (iss === "https://accounts.google.com") {
      const envs = env<{
        OIDC_GOOGLE_CLIENT: string;
        OIDC_GOOGLE_SECRET: string;
      }>(c);
      const client_id = envs.OIDC_GOOGLE_CLIENT;
      const client_secret = envs.OIDC_GOOGLE_SECRET;
      return {
        issuer: "https://accounts.google.com",
        auth_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
        token_endpoint: "https://www.googleapis.com/oauth2/v4/token",
        token_revocation_endpoint: "https://oauth2.googleapis.com/revoke",
        jwks_uri: "https://www.googleapis.com/oauth2/v3/certs",
        client_id,
        client_secret,
      };
    }
    return undefined;
  }
  async getIssuerFromToken(
    c: Context,
    token: string,
  ): Promise<"https://accounts.google.com" | undefined> {
    const payload = decodeJwt(token);
    if (!payload?.iss) {
      return undefined;
    }
    if (payload.iss !== "https://accounts.google.com") {
      return undefined;
    }
    return payload.iss;
  }
  async getPayloadFromToken(
    c: Context,
    token: string,
  ): Promise<JWTPayload | undefined> {
    const iss = await this.getIssuerFromToken(c, token);
    const metadata = await this.getIssuerMetadata(c, iss);
    let payload: JWTPayload | undefined = undefined;
    let idToken: string | undefined = token;
    for (let i = 2 /* 検証回数 */; i > 0; i--) {
      try {
        if (idToken) {
          const jwks = createRemoteJWKSet(new URL(metadata.jwks_uri));
          payload = (
            await jwtVerify(idToken, jwks, {
              issuer: metadata.issuer,
              audience: metadata.client_id,
            })
          ).payload;
          if (payload.iss !== metadata.issuer) {
            // ID Token の発行者が異なる場合は無効とする
            // iss Claimはオプショナルだが、このモジュールでは必須
            throw new Error("Invalid issuer");
          }
          // ID Token の検証に成功した場合
          this.setIDToken(c, {
            token: idToken,
            payload,
          });
          return payload;
        }
        throw new Error("ID Token is empty (maybe logout-state)");
      } catch (_error) {
        if (i > 1) {
          // 最後のループ以外はトークンの再取得を試行する
          idToken = undefined;
          const refresh_token = await this.getRefreshToken(c);
          if (refresh_token) {
            const tokenResponse = await fetch(metadata.token_endpoint, {
              method: "POST",
              headers: {
                "Content-Type": "application/x-www-form-urlencoded",
              },
              body: new URLSearchParams({
                refresh_token,
                client_id: metadata.client_id,
                client_secret: metadata.client_secret,
                grant_type: "refresh_token",
              }),
            });
            const tokenData = tokenResponse
              ? await tokenResponse.json()
              : (undefined as any);
            const mayIDToken = tokenData?.id_token;
            if (typeof mayIDToken === "string") {
              // ID Token の取得に成功した場合は再度検証を試みる
              idToken = mayIDToken as string;
            }
          }
        } else {
          return undefined;
        }
      }
    }
  }

  override async getRefreshToken(c: Context): Promise<string | undefined> {
    return getCookie(c, "refresh_token");
  }
  override async setRefreshToken(
    c: Context,
    token: string | undefined,
  ): Promise<void> {
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
  }

  override async getIDToken(c: Context): Promise<string | undefined> {
    return getCookie(c, "id_token");
  }
  override async setIDToken(
    c: Context,
    keys: { token: string; payload: JWTPayload } | undefined,
  ): Promise<void> {
    if (!keys) {
      deleteCookie(c, "id_token");
      return;
    }
    const { token } = keys;
    const reqUrl = new URL(c.req.url);
    const secure = reqUrl.hostname !== "localhost";
    return setCookie(c, "id_token", token, {
      path: "/",
      sameSite: "Lax",
      httpOnly: true,
      secure,
      maxAge: COOKIE_MAXAGE,
    });
  }
}
```

### Create Login and Logout Routes

Add login and logout routes using `loginHandler` and `logoutHandler`.

```ts
import { Hono } from "hono";

const app = new Hono();
const oidc = new Oidc();

app.get(
  "/login",
  oidc.loginHandler("https://accounts.google.com", (c, res) => {
    if (res.error) {
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

app.get("/logout", oidc.logoutHandler((c) => c.redirect("/")));
```

### Create Middleware for Authentication

You can require authentication for specific routes using your middleware like so:

```ts
app.use("/protected", async (c, next) => {
  const payload = await oidc.getPayload(c);
  if (!payload) {
    return c.redirect("/login");
  }
  return await next();
});
```

## License

Apache-2.0
