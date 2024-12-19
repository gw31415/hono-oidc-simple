import type { Context } from "hono";
import { sign, verify } from "hono/jwt";
import type { BlankInput, Handler, Input, MiddlewareHandler } from "hono/types";
import type { SignatureAlgorithm } from "hono/utils/jwt/jwa";
import type { SignatureKey } from "hono/utils/jwt/jws";
import { JwtTokenExpired } from "hono/utils/jwt/types";

type NonNull = Record<never, never>;

/** Custom claims for JWT tokens */
export type CustomClaims = {
  [key: Exclude<string, "exp">]: NonNull | undefined;
};

/**
 * Metadata for an OpenID Connect Issuer.
 * @template Issuer Union of the const-strings that represent Issuer URLs.
 */
interface AbstractIssuerMetadata<IU extends string> {
  /** OpenID Connect Issuer */
  issuer: IU;
  /** OpenID Connect authentication endpoint */
  auth_endpoint: string;
  /** OpenID Connect token endpoint */
  token_endpoint: string;
  /** OpenID Connect token revocation endpoint */
  token_revocation_endpoint: string;
  /** OpenID Connect client ID */
  client_id: string;
  /** OpenID Connect client secret */
  client_secret: string;
  /** OpenID Connect scopes */
  scopes: string[];
}

/**
 * Options for local JWT signing.
 */
interface LocalJwtOptions {
  /** Private key for signing */
  privateKey: SignatureKey;
  /** Signature algorithm */
  alg?: SignatureAlgorithm;
  /** Validity period (in milliseconds) */
  maxAge: number;
}

/**
 * Metadata for an OpenID Connect Issuer.
 * @template I Union of the const-strings that represent Issuer URLs.
 */
export type IssuerMetadata<C extends CustomClaims, IU extends string> =
  | (AbstractIssuerMetadata<IU> & {
      /** Indicates if the Issuer supports refresh tokens */
      supports_refresh: false;
      /** Options for creating custom JWT when no refresh token is available */
      local_jwt_options: LocalJwtOptions;
      createClaims: (
        c: Context,
        tokens: RefreshTokenGetter,
      ) => C | undefined | Promise<C | undefined>;
    })
  | (AbstractIssuerMetadata<IU> & {
      /** Indicates if the Issuer supports refresh tokens */
      supports_refresh: true;
      createClaims: (c: Context, tokens: TokenGetter) => C | Promise<C>;
    });

/**
 * Options for OpenID Connect.
 * @template C Custom claims for JWT tokens
 * @template IU Union of the const-strings that represent Issuer URLs.
 */
export interface OidcOptions<C extends CustomClaims, IU extends string> {
  /** Issuer metadata */
  issuers: IssuerMetadata<C, IU>[];
  /** Function to get the Issuer URL */
  getIssUrl: (c: Context) => IU | Promise<IU> | undefined;
  /** Client-side token store */
  clientSideTokenStore: TokenStore;
}

interface RefreshTokenSetter {
  setRefreshToken(c: Context, token: string | undefined): void | Promise<void>;
}

interface IDTokenSetter {
  setIDToken(c: Context, token: string | undefined): void | Promise<void>;
}

interface IDTokenGetter {
  getIDToken(c: Context): string | undefined | Promise<string | undefined>;
}

interface RefreshTokenGetter {
  getRefreshToken(c: Context): string | undefined | Promise<string | undefined>;
}

type TokenSetter = IDTokenSetter & RefreshTokenSetter;

type TokenGetter = IDTokenGetter & RefreshTokenGetter;

type TokenStore = TokenGetter & TokenSetter;

const CacheStore = ({
  cache,
  src,
}: { src: TokenStore; cache: TokenStore }): TokenStore => {
  const inner: TokenStore = {
    getIDToken: async (c) => {
      let token = await cache.getIDToken(c);
      if (!token) {
        token = await src.getIDToken(c);
        await cache.setIDToken(c, token);
      }
      return token;
    },
    getRefreshToken: async (c) => {
      let token = await cache.getRefreshToken(c);
      if (!token) {
        token = await src.getRefreshToken(c);
        await cache.setRefreshToken(c, token);
      }
      return token;
    },
    setIDToken: async (c, token) => {
      await src.setIDToken(c, token);
      await cache.setIDToken(c, token);
    },
    setRefreshToken: async (c, token) => {
      await src.setRefreshToken(c, token);
      await cache.setRefreshToken(c, token);
    },
  };
  return inner;
};

const InMemoryStore = (): TokenStore => {
  let itoken: string | undefined = undefined;
  let rtoken: string | undefined = undefined;
  return {
    getIDToken: () => itoken,
    getRefreshToken: () => rtoken,
    setIDToken: (_, token) => {
      itoken = token;
    },
    setRefreshToken: (_, token) => {
      rtoken = token;
    },
  };
};

const OIDCVirtualStore = <C extends CustomClaims, IU extends string>(
  _: Context,
  opts: {
    iss: IssuerMetadata<C, IU>;
    token: TokenStore;
  },
): TokenStore => {
  const refreshTokenStore: RefreshTokenSetter & RefreshTokenGetter =
    InMemoryStore();
  const inner: TokenStore = {
    async getIDToken(c) {
      const itoken = opts.token.getIDToken(c);
      if (itoken) {
        return itoken;
      }

      // Refresh
      const rtoken = await inner.getRefreshToken(c);
      if (!rtoken) {
        return undefined;
      }

      const metadata = opts.iss;

      if (!metadata.supports_refresh) {
        const { privateKey, alg, maxAge } = metadata.local_jwt_options;

        const claims = await metadata.createClaims(c, {
          getRefreshToken: () => rtoken,
        });
        if (!claims) {
          return undefined;
        }

        // Re-issue with a refresh token if expired
        const exp = Math.floor((Date.now() + maxAge) / 1000) + 1;
        const token = await sign(
          {
            ...claims,
            exp,
          },
          privateKey,
          alg,
        );
        return token;
      }

      const tokenResponse = await fetch(metadata.token_endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          refresh_token: rtoken,
          client_id: metadata.client_id,
          client_secret: metadata.client_secret,
          grant_type: "refresh_token",
        }),
      });
      const tokenData = tokenResponse
        ? ((await tokenResponse.json()) as CustomClaims | undefined)
        : undefined;
      const mayIDToken = tokenData?.id_token;
      if (typeof mayIDToken === "string") {
        // If ID Token is successfully obtained, attempt verification again
        return mayIDToken;
      }
      return undefined;
    },
    getRefreshToken: refreshTokenStore.getRefreshToken,
    async setIDToken(c, token) {
      const metadata = opts.iss;
      if (!token) {
        if (metadata.supports_refresh) {
          const id_token = await opts.token.getIDToken(c);
          if (id_token) {
            await fetch(metadata.token_revocation_endpoint, {
              method: "POST",
              headers: {
                "Content-Type": "application/x-www-form-urlencoded",
              },
              body: new URLSearchParams({
                token: id_token,
                client_id: metadata.client_id,
                client_secret: metadata.client_secret,
              }),
            }).catch(() => {});
          }
        }
      } else {
        await opts.token.setIDToken(c, token);
      }
    },
    async setRefreshToken(c, token) {
      await refreshTokenStore.setRefreshToken(c, token);
      if (!token) {
        const metadata = opts.iss;
        const refresh_token = await opts.token.getRefreshToken(c);
        if (refresh_token) {
          if (metadata.supports_refresh) {
            inner.setIDToken(c, undefined); // Cascade
          }
          await fetch(metadata.token_revocation_endpoint, {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: new URLSearchParams({
              token: refresh_token,
              client_id: metadata.client_id,
              client_secret: metadata.client_secret,
            }),
          }).catch(() => {});
        }
      } else {
        await opts.token.setRefreshToken(c, token);
      }
    },
  };
  return inner;
};

/**
 * Middleware to use OpenID Connect.
 * @template C Custom claims for JWT tokens
 * @template IU Union of the const-strings that represent Issuer URLs.
 * @param opts OIDC options
 * @returns Middleware
 */
export const oidc = <C extends CustomClaims, IU extends string>(
  opts:
    | OidcOptions<C, IU>
    | ((c: Context) => OidcOptions<C, IU> | Promise<OidcOptions<C, IU>>),
): MiddlewareHandler<{
  Variables: {
    __oidc: OIDC<C, IU>;
  };
}> => {
  return async (c, n) => {
    if (c.get("__oidc")) {
      await n();
      return;
    }
    const o = typeof opts === "function" ? await opts(c) : opts;
    const oidc = await OIDC.create(c, o);
    c.set("__oidc", oidc);
    await n();
  };
};

/**
 * Middleware to obtain claims from OpenID Connect.
 * @template C Custom claims for JWT tokens
 * @template IU Union of the const-strings that represent Issuer URLs.
 */
export const useClaims = <
  C extends CustomClaims,
  IU extends string,
>(): MiddlewareHandler<{
  Variables: {
    __oidc: OIDC<C, IU>;
    claims: C | undefined;
  };
}> => {
  return async (c, n) => {
    const oidc = c.get("__oidc")!;
    const claims = await oidc.getClaims(c);
    c.set("claims", claims);
    await n();
  };
};

/**
 * Logout handler for OpenID Connect.
 * @template P Path parameters
 * @template I Input
 * @param callback Callback function
 * @returns Handler
 */
export const logoutHandler = <
  P extends string = any,
  I extends Input = BlankInput,
>(
  callback: (...args: Parameters<Handler>) => ReturnType<Handler>,
): Handler<any, P, I> => {
  return async (c, ...args) => {
    const oidc = c.get("__oidc")!;
    await oidc.logout(c);
    return callback(c, ...args);
  };
};

/**
 * Login handler for OpenID Connect.
 * @template C Custom claims for JWT tokens
 * @template IU Union of the const-strings that represent Issuer URLs.
 * @template P Path parameters
 * @template I Input
 * @param iss Issuer URL
 * @param callback Callback function
 * @returns Handler
 */
export const loginHandler = <
  C extends CustomClaims,
  IU extends string,
  P extends string = any,
  I extends Input = BlankInput,
>(
  iss: IU,
  callback: (
    res:
      | {
          type: "OK";
          claims: C;
        }
      | {
          type: "ERR";
          error: "OAuthServerError";
        }
      | {
          type: "ERR";
          error: "Unauthorized";
        },
    ...args: Parameters<Handler>
  ) => ReturnType<Handler>,
): Handler<any, P, I> => {
  return async (c, ...args) => {
    const oidc = c.get("__oidc")!;
    const res = await oidc.login(c, iss);

    switch (res.type) {
      case "RESPONSE":
        return res.response;
      case "OK":
        c.set("claims", res.claims);
    }
    return callback(res, c, ...args);
  };
};

/**
 * Internal OpenID Connect client.
 * @template C Custom claims for JWT tokens
 * @template IU Union of the const-strings that represent Issuer URLs.
 */
class OIDC<C extends CustomClaims, IU extends string> {
  readonly #tokens: TokenStore;
  readonly #opts: OidcOptions<C, IU>;

  private constructor(arg: {
    tokens: TokenStore;
    opts: OidcOptions<C, IU>;
  }) {
    this.#tokens = arg.tokens;
    this.#opts = arg.opts;
  }

  /**
   * Create an OIDC client.
   * @param c Context
   * @param opts OIDC options
   * @returns OIDC client
   */
  static async create<C extends CustomClaims, IU extends string>(
    c: Context,
    opts: OidcOptions<C, IU>,
  ): Promise<OIDC<C, IU>> {
    const issurl = await opts.getIssUrl(c);
    const iss = opts.issuers.find((i) => i.issuer === issurl);
    if (!iss) {
      throw new Error("Issuer not found");
    }
    const clientSideTokenStore = CacheStore({
      cache: InMemoryStore(),
      src: opts.clientSideTokenStore,
    });
    const tokens: TokenStore = CacheStore({
      cache: clientSideTokenStore,
      src: OIDCVirtualStore(c, {
        iss,
        token: clientSideTokenStore,
      }),
    });
    return new OIDC({
      tokens,
      opts,
    });
  }

  async #getIssuerMetadata(
    c: Context,
  ): Promise<IssuerMetadata<C, IU> | undefined> {
    const issurl = await this.#opts.getIssUrl(c);
    if (!issurl) {
      return undefined;
    }
    const iss = this.#opts.issuers.find((i) => i.issuer === issurl);
    if (!iss) {
      throw new Error("Issuer not found");
    }
    return iss;
  }

  /**
   * Manually Login with OpenID Connect.
   * @param c Context
   * @param issurl OpenID Connect Issuer URL
   * @returns Login result. If the login is successful, the claims are
   * returned.
   */
  public async login(
    c: Context,
    issurl: IU,
  ): Promise<
    | {
        type: "OK";
        claims: C;
      }
    | {
        type: "ERR";
        error: "OAuthServerError";
      }
    | {
        type: "ERR";
        error: "Unauthorized";
      }
    | {
        type: "RESPONSE";
        response: Response;
      }
  > {
    const metadata = this.#opts.issuers.find((i) => i.issuer === issurl);
    if (!metadata) {
      return {
        type: "ERR",
        error: "Unauthorized",
      };
    }
    const reqUrl = new URL(c.req.url);
    // Redirect URI is the same URL
    const redirect_uri = reqUrl.origin + reqUrl.pathname;

    const code = reqUrl.searchParams.get("code");
    let token: undefined | string = undefined;

    if (code) {
      // If an authorization code is received
      // Request token with authorization code
      const tokenResponse = await fetch(metadata.token_endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          code,
          client_id: metadata.client_id,
          client_secret: metadata.client_secret,
          redirect_uri,
          grant_type: "authorization_code",
        }),
      });

      const tokenData = (await tokenResponse.json()) as any;
      const mayToken = tokenData.access_token ?? tokenData.id_token;
      if (typeof mayToken !== "string") {
        return {
          type: "ERR",
          error: "OAuthServerError",
        };
      }
      if (metadata.supports_refresh) {
        // CASE1: a refresh token is available
        // Save idToken and refresh_token
        if (tokenData.refresh_token) {
          await this.#tokens.setRefreshToken(c, `${tokenData.refresh_token}`);
        }
        token = mayToken;
      } else {
        // CASE2: there is no refresh token
        // refresh_token: token
        // idToken: Convert CustomClaims to JWT and save them
        const claims: C | undefined = await metadata.createClaims(c, {
          getRefreshToken: () => mayToken,
        });
        if (!claims) {
          throw new Error("Invalid ID Token");
        }
        const exp =
          Math.floor((Date.now() + metadata.local_jwt_options.maxAge) / 1000) +
          1;
        token = await sign(
          {
            ...claims,
            exp,
          },
          metadata.local_jwt_options.privateKey,
          metadata.local_jwt_options.alg,
        );
        await this.#tokens.setIDToken(c, token);
        await this.#tokens.setRefreshToken(c, mayToken);
        return {
          type: "OK",
          claims,
        };
      }
    } else {
      token = await this.#tokens.getIDToken(c);
    }

    // ID Token Validation
    if (!token) {
      // Here there is no valid refresh_token either.
      // Considered as login start by user access
      const authUrl = new URL(metadata.auth_endpoint);
      authUrl.searchParams.append("response_type", "code");
      authUrl.searchParams.append("client_id", metadata.client_id);
      authUrl.searchParams.append("redirect_uri", redirect_uri);
      authUrl.searchParams.append("scope", metadata.scopes.join(" "));
      if (
        metadata.auth_endpoint ===
        "https://accounts.google.com/o/oauth2/v2/auth"
      ) {
        authUrl.searchParams.append("access_type", "offline");
        authUrl.searchParams.append("prompt", "consent");
      }
      return {
        type: "RESPONSE",
        response: c.redirect(authUrl.toString()),
      };
    }

    const claims = await metadata.createClaims(c, this.#tokens);
    if (!claims) {
      await this.logout(c);
      return {
        type: "ERR",
        error: "Unauthorized",
      };
    }
    // INFO: If claims can be obtained with getClaimsFromToken, the token is valid (type constraint is applied).
    await this.#tokens.setIDToken(c, token!);
    return {
      type: "OK",
      claims,
    };
  }

  public async getClaims(c: Context) {
    const idToken = await this.#tokens.getIDToken(c);
    if (!idToken) {
      await this.logout(c);
      return;
    }
    const metadata = await this.#getIssuerMetadata(c);
    if (!metadata) {
      await this.logout(c);
      return;
    }
    if (!metadata.supports_refresh) {
      const { privateKey, alg, maxAge } = metadata.local_jwt_options;
      try {
        const claims = await verify(idToken, privateKey, alg);
        return claims as C;
      } catch (e) {
        if (e instanceof JwtTokenExpired) {
          const claims = await metadata.createClaims(c, this.#tokens);
          if (!claims) {
            await this.logout(c);
            return;
          }

          // Re-issue with a refresh token if expired
          const exp = Math.floor((Date.now() + maxAge) / 1000) + 1;
          const token = await sign(
            {
              ...claims,
              exp,
            },
            metadata.local_jwt_options.privateKey,
            metadata.local_jwt_options.alg,
          );
          await this.#tokens.setIDToken(c, token);
          return claims;
        }
      }

      // Logout if idToken is invalid
      await this.logout(c);
      return undefined;
    }

    const claims = await metadata.createClaims(c, this.#tokens);
    if (claims) {
      return claims;
    }

    const refresh_token = await this.#tokens.getRefreshToken(c);
    if (!refresh_token) {
      await this.logout(c);
      return;
    }

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
      // If ID Token is successfully obtained, attempt verification again
      return await metadata.createClaims(c, {
        getIDToken: () => mayIDToken,
        getRefreshToken: () => refresh_token,
      });
    }
    return undefined;
  }

  public async logout(c: Context) {
    const idToken = await this.#tokens.getIDToken(c);
    if (idToken) {
      const metadata = await this.#getIssuerMetadata(c);
      if (metadata) {
        await fetch(metadata.token_revocation_endpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            token: idToken,
            client_id: metadata.client_id,
            client_secret: metadata.client_secret,
          }),
        }).catch(() => {});
        const refresh_token = await this.#tokens.getRefreshToken(c);
        if (refresh_token) {
          await fetch(metadata.token_revocation_endpoint, {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: new URLSearchParams({
              token: refresh_token,
              client_id: metadata.client_id,
              client_secret: metadata.client_secret,
            }),
          }).catch(() => {});
        }
      }
    }
    await this.#tokens.setRefreshToken(c, undefined);
    await this.#tokens.setIDToken(c, undefined);
  }
}
