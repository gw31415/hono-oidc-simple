import type { Context } from "hono";
import { every } from "hono/combine";
import { sign, verify } from "hono/jwt";
import type { Handler, MiddlewareHandler } from "hono/types";
import type { SignatureAlgorithm } from "hono/utils/jwt/jwa";
import type { SignatureKey } from "hono/utils/jwt/jws";
import { JwtTokenExpired } from "hono/utils/jwt/types";

/** Not-null type */
type NonNull = Record<never, never>;

//biome-ignore lint: `keyof any` is not `any` itself.
type AnyRecord<T = unknown> = Record<keyof any, T>;

/** Custom claims for JWT tokens */
type CustomClaims = {
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
  authEndpoint: string;
  /** OpenID Connect token endpoint */
  tokenEndpoint: string;
  /** OpenID Connect token revocation endpoint */
  tokenRevocationEndpoint: string;
  /** OpenID Connect client ID */
  clientId: string;
  /** OpenID Connect client secret */
  clientSecret: string;
  /** OpenID Connect scopes */
  scopes: string[];
}

/**
 * Options for local JWT signing.
 */
export interface LocalJwtOptions {
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
      useLocalJwt: true;
      /** Options for creating custom JWT when no refresh token is available */
      localJwtOptions: LocalJwtOptions;
      /** Specify how Claims are generated using token and context */
      createClaims: (
        c: Context,
        tokens: RefreshTokenGetter,
      ) => C | undefined | Promise<C | undefined>;
    })
  | (AbstractIssuerMetadata<IU> & {
      /** Indicates if the Issuer supports refresh tokens */
      useLocalJwt: false;
      /** Specify how Claims are generated using token and context */
      createClaims: (
        c: Context,
        tokens: TokenGetter,
      ) => C | undefined | Promise<C | undefined>;
    });

/**
 * Options for OpenID Connect.
 * @template C Custom claims for JWT tokens
 * @template IU Union of the const-strings that represent Issuer URLs.
 */
export interface OIDCOptions<C extends CustomClaims, IU extends string> {
  /** Issuer metadata */
  issuers: IssuerMetadata<C, IU>[];
  /** Function to get the Issuer URL */
  getIssUrl: (c: Context) => IU | Promise<IU> | undefined;
  /** Client-side token store */
  clientSideTokenStore: TokenStore;
}

/**
 * Refresh token setter.
 */
interface RefreshTokenSetter {
  setRefreshToken(c: Context, token: string | undefined): void | Promise<void>;
}

/**
 * ID token setter.
 */
interface IDTokenSetter {
  setIDToken(c: Context, token: string | undefined): void | Promise<void>;
}

/**
 * ID token getter.
 */
interface IDTokenGetter {
  getIDToken(c: Context): string | undefined | Promise<string | undefined>;
}

/**
 * Refresh token getter.
 */
interface RefreshTokenGetter {
  getRefreshToken(c: Context): string | undefined | Promise<string | undefined>;
}

/**
 * ID token & refresh token setter.
 */
type TokenSetter = IDTokenSetter & RefreshTokenSetter;

/**
 * ID token & refresh token getter.
 */
type TokenGetter = IDTokenGetter & RefreshTokenGetter;

/**
 * ID token & refresh token getter and setter.
 */
export type TokenStore = TokenGetter & TokenSetter;

/**
 * Refresh token getter and setter.
 */
type RefreshTokenStore = RefreshTokenGetter & RefreshTokenSetter;

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
  const refreshTokenStore: RefreshTokenStore = InMemoryStore();
  const inner: TokenStore = {
    async getIDToken(c) {
      const itoken = await opts.token.getIDToken(c);
      if (itoken) {
        return itoken;
      }

      // Refresh
      const rtoken = await opts.token.getRefreshToken(c);
      if (!rtoken) {
        return undefined;
      }

      const metadata = opts.iss;

      if (metadata.useLocalJwt) {
        const { privateKey, alg, maxAge } = metadata.localJwtOptions;

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

      const tokenResponse = await fetch(metadata.tokenEndpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          refresh_token: rtoken,
          client_id: metadata.clientId,
          client_secret: metadata.clientSecret,
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
        if (!metadata.useLocalJwt) {
          const id_token = await opts.token.getIDToken(c);
          if (id_token) {
            await fetch(metadata.tokenRevocationEndpoint, {
              method: "POST",
              headers: {
                "Content-Type": "application/x-www-form-urlencoded",
              },
              body: new URLSearchParams({
                token: id_token,
                client_id: metadata.clientId,
                client_secret: metadata.clientSecret,
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
          if (!metadata.useLocalJwt) {
            inner.setIDToken(c, undefined); // Cascade
          }
          await fetch(metadata.tokenRevocationEndpoint, {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: new URLSearchParams({
              token: refresh_token,
              client_id: metadata.clientId,
              client_secret: metadata.clientSecret,
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
 * Get type of OIDC
 */
type OIDCManagerType<T> = T extends OIDCManager<CustomClaims, string>
  ? T
  : T extends {
        __oidc: infer U;
      } & AnyRecord
    ? OIDCManagerType<U>
    : T extends {
          Variables: infer U;
        } & AnyRecord
      ? OIDCManagerType<U>
      : T extends MiddlewareHandler<infer U>
        ? OIDCManagerType<U>
        : T extends OIDCSetupResult<infer C, infer IU>
          ? OIDCManager<C, IU>
          : never;

/**
 * Get type of OIDC Custom Claims
 */
export type ClaimsType<T> = OIDCManagerType<T> extends OIDCManager<
  infer C,
  string
>
  ? C
  : T extends IssuerMetadata<infer C, string>
    ? C
    : T extends OIDCOptions<infer C, string>
      ? C
      : T extends CustomClaims
        ? T
        : never;

/**
 * Get type of OIDC Issuer URL
 */
export type IssuerType<T> = OIDCManagerType<T> extends OIDCManager<
  CustomClaims,
  infer IU
>
  ? IU
  : T extends IssuerMetadata<CustomClaims, infer IU>
    ? IU
    : T extends OIDCOptions<CustomClaims, infer IU>
      ? IU
      : T extends string
        ? T
        : never;

export type OIDCMiddlewareType<T> = T extends OIDCMiddleware<CustomClaims>
  ? T
  : ClaimsType<T> extends CustomClaims
    ? OIDCMiddleware<ClaimsType<T>>
    : never;

type OIDCEnv<C extends CustomClaims> = {
  Variables: {
    claims: C | undefined;
  } & AnyRecord;
};

type OIDCInternalEnv<C extends CustomClaims, IU extends string> = {
  Variables: {
    __oidc: OIDCManager<C, IU> | undefined;
    claims: C | undefined;
  } & AnyRecord;
} & AnyRecord;

type OIDCInternalMiddleware<
  C extends CustomClaims,
  IU extends string,
> = MiddlewareHandler<OIDCInternalEnv<C, IU>>;

type OIDCMiddleware<C extends CustomClaims> = MiddlewareHandler<OIDCEnv<C>>;

type OIDCInternalHandler<C extends CustomClaims, IU extends string> = Handler<
  OIDCInternalEnv<C, IU>
>;

type OIDCHandler<C extends CustomClaims> = Handler<OIDCEnv<C>>;

/**
 * @template C Custom claims for JWT tokens
 * @template IU Union of the const-strings that represent Issuer URLs.
 * @template P Path parameters
 * @template I Input
 */
export interface OIDCSetupResult<C extends CustomClaims, IU extends string> {
  /**
   * Login handler for OpenID Connect.
   * @param iss Issuer URL
   * @param callback Callback function
   * @returns Handler
   */
  loginHandler: (
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
      ...args: Parameters<OIDCHandler<C>>
    ) => ReturnType<OIDCHandler<C>>,
  ) => OIDCHandler<C>;

  /**
   * Middleware to obtain claims from OpenID Connect.
   */
  useClaims: OIDCMiddleware<C>;

  /**
   * Logout handler for OpenID Connect.
   * @param callback Callback function
   * @returns Handler
   */
  logoutHandler: (callback: Handler) => Handler;
}

export const OIDC = <C extends CustomClaims, IU extends string>(
  opts:
    | OIDCOptions<C, IU>
    | ((c: Context) => OIDCOptions<C, IU> | Promise<OIDCOptions<C, IU>>),
): OIDCSetupResult<C, IU> => {
  const useOIDC: OIDCInternalMiddleware<C, IU> = async (c, n) => {
    if (c.get("__oidc")) {
      await n();
      return;
    }
    const o = typeof opts === "function" ? await opts(c) : opts;
    const oidc = await OIDCManager.create(c, o);
    c.set("__oidc", oidc);
    await n();
  };
  return {
    loginHandler: (iss, callback) =>
      every(useOIDC, (async (c, ...args) => {
        const oidc = c.get("__oidc")!;
        const res = await oidc.login(c, iss);

        switch (res.type) {
          case "RESPONSE":
            return res.response;
          case "OK":
            c.set("claims", res.claims);
        }
        return await callback(
          res,
          c as unknown as Context<OIDCEnv<C>>,
          ...args,
        );
      }) satisfies OIDCInternalHandler<C, IU>),
    useClaims: every(useOIDC, async (c, n) => {
      const oidc = c.get("__oidc")!;
      const claims = await oidc.getClaims(c);
      c.set("claims", claims);
      await n();
    }),
    logoutHandler: (callback) =>
      every(useOIDC, (async (c, ...args) => {
        const oidc = c.get("__oidc")!;
        await oidc.logout(c);
        return await callback(c, ...args);
      }) satisfies OIDCInternalHandler<C, IU>),
  };
};

/**
 * Internal OpenID Connect client.
 * @template C Custom claims for JWT tokens
 * @template IU Union of the const-strings that represent Issuer URLs.
 */
class OIDCManager<C extends CustomClaims, IU extends string> {
  readonly #tokens: TokenStore;
  readonly #opts: OIDCOptions<C, IU>;

  private constructor(arg: {
    tokens: TokenStore;
    opts: OIDCOptions<C, IU>;
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
    opts: OIDCOptions<C, IU>,
  ): Promise<OIDCManager<C, IU>> {
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
    return new OIDCManager({
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
      const tokenResponse = await fetch(metadata.tokenEndpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          code,
          client_id: metadata.clientId,
          client_secret: metadata.clientSecret,
          redirect_uri,
          grant_type: "authorization_code",
        }),
      });

      const tokenData: AnyRecord | null = await tokenResponse.json();
      if (!(tokenData instanceof Object)) {
        return {
          type: "ERR",
          error: "OAuthServerError",
        };
      }
      const mayToken = tokenData.id_token ?? tokenData.access_token;
      if (typeof mayToken !== "string") {
        return {
          type: "ERR",
          error: "OAuthServerError",
        };
      }
      if (!metadata.useLocalJwt) {
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
          Math.floor((Date.now() + metadata.localJwtOptions.maxAge) / 1000) + 1;
        token = await sign(
          {
            ...claims,
            exp,
          },
          metadata.localJwtOptions.privateKey,
          metadata.localJwtOptions.alg,
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
      const authUrl = new URL(metadata.authEndpoint);
      authUrl.searchParams.append("response_type", "code");
      authUrl.searchParams.append("client_id", metadata.clientId);
      authUrl.searchParams.append("redirect_uri", redirect_uri);
      authUrl.searchParams.append("scope", metadata.scopes.join(" "));
      if (
        metadata.authEndpoint === "https://accounts.google.com/o/oauth2/v2/auth"
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
    await this.#tokens.setIDToken(c, token);
    return {
      type: "OK",
      claims,
    };
  }

  public async getClaims(c: Context): Promise<C | undefined> {
    const metadata = await this.#getIssuerMetadata(c);
    if (!metadata) {
      await this.logout(c);
      return;
    }
    if (metadata.useLocalJwt) {
      const { privateKey, alg, maxAge } = metadata.localJwtOptions;
      try {
        const idToken = await this.#tokens.getIDToken(c);
        if (!idToken) {
          throw new JwtTokenExpired("");
        }
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
            metadata.localJwtOptions.privateKey,
            metadata.localJwtOptions.alg,
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

    const tokenResponse = await fetch(metadata.tokenEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        refresh_token,
        client_id: metadata.clientId,
        client_secret: metadata.clientSecret,
        grant_type: "refresh_token",
      }),
    });
    const tokenData: AnyRecord | null = tokenResponse
      ? await tokenResponse.json()
      : null;
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

  public async logout(c: Context): Promise<void> {
    const idToken = await this.#tokens.getIDToken(c);
    if (idToken) {
      const metadata = await this.#getIssuerMetadata(c);
      if (metadata) {
        await fetch(metadata.tokenRevocationEndpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            token: idToken,
            client_id: metadata.clientId,
            client_secret: metadata.clientSecret,
          }),
        }).catch(() => {});
        const refresh_token = await this.#tokens.getRefreshToken(c);
        if (refresh_token) {
          await fetch(metadata.tokenRevocationEndpoint, {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: new URLSearchParams({
              token: refresh_token,
              client_id: metadata.clientId,
              client_secret: metadata.clientSecret,
            }),
          }).catch(() => {});
        }
      }
    }
    await this.#tokens.setRefreshToken(c, undefined);
    await this.#tokens.setIDToken(c, undefined);
  }
}
