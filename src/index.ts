import type { Context } from "hono";
import { createFactory } from "hono/factory";
import { decode, sign, verify } from "hono/jwt";
import type { Env, Handler, HandlerResponse } from "hono/types";
import type { SignatureAlgorithm } from "hono/utils/jwt/jwa";
import type { SignatureKey } from "hono/utils/jwt/jws";
import { JwtTokenExpired } from "hono/utils/jwt/types";

// Reference： https://github.com/honojs/honox/blob/f2094e35/src/factory/factory.ts#L6
const factory = createFactory<Env>();
const createHandlers = factory.createHandlers;

/** 認証エラーの種類 */
export type OidcError = "OAuthServerError" | "Unauthorized";

interface AbstractIssuerMetadata<Issuer extends string | unknown> {
  /** OpenID Connect の Issuer */
  issuer: MustIssuer<Issuer>;
  /** OpenID Connect の認証エンドポイント */
  auth_endpoint: string;
  /** OpenID Connect のトークンエンドポイント */
  token_endpoint: string;
  /** OpenID Connect のトークンリボケーションエンドポイント */
  token_revocation_endpoint: string;
  /** OpenID Connect のクライアント ID */
  client_id: string;
  /** OpenID Connect のクライアントシークレット */
  client_secret: string;
  /** OpenID Connect のスコープ */
  scopes: string[];
}

interface LocalJwtOptions {
  /** 署名用の秘密鍵 */
  privateKey: SignatureKey;
  /** 署名アルゴリズム */
  alg?: SignatureAlgorithm;
  /** 有効寿命(ミリ秒) */
  maxAge: number;
}

/** OpenIDのIssuerのメタデータ */
export type IssuerMetadata<Issuer extends string | unknown = unknown> =
  | (AbstractIssuerMetadata<Issuer> & {
      /** Issuerがリフレッシュトークンを発行するか */
      token_refreshable: false;
      /** Refresh Tokenが用意されない時、独自JWTを作成するためのオプション */
      local_jwt_options: LocalJwtOptions;
    })
  | (AbstractIssuerMetadata<Issuer> & {
      /** Issuerがリフレッシュトークンを発行するか */
      token_refreshable: true;
    });

/** Issuer URLが期待されるが、他の文字列も入ってくる可能性がある型 */
export type MayIssuer<Issuer extends string | unknown> = Issuer extends string
  ? Issuer | (string & Record<never, never>)
  : string;

/** Issuer URLのみが許容される型 */
export type MustIssuer<Issuer extends string | unknown> = Issuer extends string
  ? Issuer
  : string;

export type CustomClaims = {
  [key: Exclude<string, "exp">]: any | undefined;
};

/** OpenID Connect のハンドラやミドルウェアのセット */
export abstract class Oidc<
  Issuer extends string | unknown = unknown,
  Claims extends CustomClaims = CustomClaims,
> {
  /** Issuer URL からメタデータを取得 */
  protected abstract getIssuerMetadata(
    c: Context,
    iss: MayIssuer<Issuer>,
  ): Promise<
    IssuerMetadata<Issuer extends string ? Issuer : string> | undefined
  >;

  /** 保存したリフレッシュトークンを取得する方法 (例：Cookie から取得) */
  protected abstract getRefreshToken(c: Context): Promise<string | undefined>;
  /** リフレッシュトークンを保存する方法 (例：Cookie に保存) */
  protected abstract setRefreshToken(
    c: Context,
    token: string | null,
  ): Promise<void>;
  /** 保存した ID トークンを取得する方法 (例：Cookie から取得) */
  protected abstract getIDToken(c: Context): Promise<string | undefined>;
  /** ID トークンを保存する方法 (例：JWTに変換してCookie に保存) */
  protected abstract setIDToken(
    c: Context,
    keys: {
      token: string;
      claims: Claims;
    } | null,
  ): Promise<void>;

  /** アクセストークンからIssuer URLを取得。 */
  protected abstract getIssuerFromToken(
    c: Context,
    token: string | undefined,
    tryJwtDecode: () =>
      | (Claims & {
          exp: number;
        })
      | undefined,
  ): Promise<MustIssuer<Issuer> | undefined>;
  /** トークンをカスタムClaimsに変換 */
  protected abstract createClaimsWithToken(
    c: Context,
    token: string,
  ): Promise<Claims | undefined>;

  /** トークン無効化・ログアウト処理 */
  private async logout(c: Context): Promise<void> {
    const idToken = await this.getIDToken(c);
    if (idToken) {
      const iss = await this.getIssuerFromToken(c, idToken, () => {
        try {
          const claims = decode(idToken).payload as Claims & {
            exp: number;
          };
          return claims;
        } catch {
          return undefined;
        }
      }).catch(() => undefined);
      const metadata =
        iss === undefined ? undefined : await this.getIssuerMetadata(c, iss);
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
        const refresh_token = await this.getRefreshToken(c);
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
    await this.setRefreshToken(c, null);
    await this.setIDToken(c, null);
  }

  /** 現在のトークンを検証しカスタムClaimsを取得 */
  public async getCustomClaims(c: Context): Promise<Claims | undefined> {
    const idToken = await this.getIDToken(c);
    if (!idToken) {
      await this.logout(c);
      return;
    }
    const iss = await this.getIssuerFromToken(c, idToken, () => {
      try {
        const claims = decode(idToken).payload as Claims & {
          exp: number;
        };
        return claims;
      } catch {
        return undefined;
      }
    }).catch(() => undefined);
    const metadata =
      iss === undefined ? undefined : await this.getIssuerMetadata(c, iss);
    if (!metadata) {
      await this.logout(c);
      return;
    }
    if (!metadata.token_refreshable) {
      const { privateKey, alg, maxAge } = metadata.local_jwt_options;
      try {
        const claims = await verify(idToken, privateKey, alg);
        return claims as Claims;
      } catch (e) {
        if (e instanceof JwtTokenExpired) {
          const external_request_token = await this.getRefreshToken(c);
          const claims =
            external_request_token === undefined
              ? undefined
              : await this.createClaimsWithToken(c, external_request_token);
          if (!claims) {
            await this.logout(c);
            return;
          }

          // 有効期限切れの場合はリフレッシュトークンを使用して再発行
          const exp = Math.floor((Date.now() + maxAge) / 1000) + 1;
          const token = await sign(
            {
              ...claims,
              exp,
            },
            metadata.local_jwt_options.privateKey,
            metadata.local_jwt_options.alg,
          );
          await this.setIDToken(c, { token, claims });
          return claims;
        }
      }

      // idToken が不正な場合はログアウト
      await this.logout(c);
      return undefined;
    }

    const claims = await this.createClaimsWithToken(c, idToken);
    if (claims) {
      return claims;
    }

    const refresh_token = await this.getRefreshToken(c);
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
      // ID Token の取得に成功した場合は再度検証を試みる
      return await this.createClaimsWithToken(c, mayIDToken);
    }
    return undefined;
  }

  /** ログアウト用ハンドラ */
  public logoutHandler<T extends Handler>(callback: T) {
    return createHandlers(async (c, n) => {
      await this.logout(c);
      return await callback(c, n);
    });
  }

  /** ログイン用ハンドラ */
  public loginHandler(
    iss: MustIssuer<Issuer>,
    callback: (
      c: Context,
      res:
        | { claims: Claims; error?: undefined }
        | { error: OidcError; claims?: undefined },
    ) => Promise<HandlerResponse<any>> | HandlerResponse<any>,
  ) {
    return createHandlers(async (c: Context) => {
      const metadata = await this.getIssuerMetadata(c, iss);
      if (!metadata) {
        return callback(c, { error: "Unauthorized" });
      }
      const reqUrl = new URL(c.req.url);
      // リダイレクト URI は同じURL
      const redirect_uri = reqUrl.origin + reqUrl.pathname;

      const code = reqUrl.searchParams.get("code");
      let token = undefined;

      if (code) {
        // 認可コードを受け取った場合
        // 認可コードを使用してトークンをリクエスト
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
          return callback(c, { error: "OAuthServerError" });
        }
        if (metadata.token_refreshable) {
          // リフレッシュトークンがある場合
          // idToken と refresh_token を保存
          if (tokenData.refresh_token) {
            await this.setRefreshToken(c, `${tokenData.refresh_token}`);
          }
          token = mayToken;
        } else {
          // リフレッシュトークンがない場合
          // refresh_token: token
          // idToken: 独自ClaimsをJWTに変換して保存
          const claims: Claims | undefined = await this.createClaimsWithToken(
            c,
            mayToken,
          );
          if (!claims) {
            throw new Error("Invalid ID Token");
          }
          const exp =
            Math.floor(
              (Date.now() + metadata.local_jwt_options.maxAge) / 1000,
            ) + 1;
          token = await sign(
            {
              ...claims,
              exp,
            },
            metadata.local_jwt_options.privateKey,
            metadata.local_jwt_options.alg,
          );
          await this.setIDToken(c, { token, claims });
          await this.setRefreshToken(c, mayToken);
          return callback(c, { claims: claims });
        }
      } else {
        token = await this.getIDToken(c);
      }

      // ID Token の検証
      if (!token) {
        // 有効なrefresh_tokenもないということ
        // ユーザーのアクセスによるログイン開始と見なす
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
        return c.redirect(authUrl.toString());
      }

      const external_request_token = metadata.token_refreshable
        ? token
        : await this.getRefreshToken(c);
      const claims =
        external_request_token === undefined
          ? undefined
          : await this.createClaimsWithToken(c, external_request_token);
      if (!claims) {
        await this.logout(c);
        return callback(c, { error: "Unauthorized" });
      }
      // INFO: getClaimsFromToken で claims が取得できた場合はトークンは有効(なように型制約している)
      await this.setIDToken(c, { token: token!, claims });
      return callback(c, { claims });
    });
  }
}
