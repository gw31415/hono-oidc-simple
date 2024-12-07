import type { Context } from "npm:hono@4.6.9";
import type {
  Handler,
  HandlerResponse,
  Next,
  TypedResponse,
} from "npm:hono@4.6.9/types";
import type { StatusCode } from "npm:hono@4.6.9/utils/http-status";
import {
  createRemoteJWKSet,
  decodeJwt,
  type JWTPayload,
  jwtVerify,
} from "npm:jose@5.9.6";
export type { JWTPayload } from "npm:jose@5.9.6";

/** 認証エラーの種類 */
export type OIDCError = "OAuthServerError" | "Unauthorized";

/** OpenIDのIssuerのメタデータ */
export interface IssuerMetadata<Issuer extends string | unknown = unknown> {
  /** OpenID Connect の Issuer */
  issuer: MustIssuer<Issuer>;
  /** OpenID Connect の認証エンドポイント */
  auth_endpoint: string;
  /** OpenID Connect のトークンエンドポイント */
  token_endpoint: string;
  /** OpenID Connect のトークンリボケーションエンドポイント */
  token_revocation_endpoint: string;
  /** OpenID Connect の JWKS URI */
  jwks_uri: string;
  /** OpenID Connect のクライアント ID */
  client_id: string;
  /** OpenID Connect のクライアントシークレット */
  client_secret: string;
}

/** Issuer URLが期待されるが、他の文字列も入ってくる可能性がある型 */
export type MayIssuer<Issuer extends string | unknown> = Issuer extends string
  ? Issuer | (string & Record<never, never>)
  : string;

/** Issuer URLのみが許容される型 */
export type MustIssuer<Issuer extends string | unknown> = Issuer extends string
  ? Issuer
  : string;

/** OpenID Connect のハンドラやミドルウェアのセット */
export abstract class Oidc<Issuer extends string | unknown = unknown> {
  /** Issuer URL からメタデータを取得 */
  protected abstract getIssuerMetadata(
    c: Context,
    iss: MayIssuer<Issuer>,
  ): Promise<
    IssuerMetadata<Issuer extends string ? Issuer : string> | undefined
  >;

  /** 保存したリフレッシュトークンを取得する方法 (例：Cookie から取得) */
  protected abstract getRefreshToken(c: Context): Promise<string | undefined>;
  /** リフレッシュトークンを保存する方法 */
  protected abstract setRefreshToken(
    c: Context,
    token: string | undefined,
  ): Promise<void>;
  /** 保存した ID トークンを取得する方法 (例：Cookie から取得) */
  protected abstract getIDToken(c: Context): Promise<string | undefined>;
  /** ID トークンを保存する方法 */
  protected abstract setIDToken(
    c: Context,
    keys:
      | {
          token: string;
          payload: JWTPayload;
        }
      | undefined,
  ): Promise<void>;

  /** アクセストークンからIssuer URLを取得 */
  private getIssuerMetadataOf(
    c: Context,
    token: string | undefined,
  ): Promise<IssuerMetadata | undefined> {
    if (!token) {
      return Promise.resolve(undefined);
    }
    const payload = decodeJwt(token);
    if (!payload?.iss) {
      return Promise.resolve(undefined);
    }
    return this.getIssuerMetadata(
      c,
      payload.iss as Issuer extends string ? Issuer : string, // TODO
    );
  }

  /** トークン無効化・ログアウト処理 */
  private async logout(c: Context): Promise<void> {
    const accessToken = await this.getIDToken(c);
    if (accessToken) {
      const metadata = await this.getIssuerMetadataOf(c, accessToken);
      if (metadata) {
        await fetch(metadata.token_revocation_endpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            token: accessToken,
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
    await this.setRefreshToken(c, undefined);
    await this.setIDToken(c, undefined);
  }

  /** 現在のトークンを検証しペイロードを取得 */
  public async getPayload(c: Context): Promise<JWTPayload | undefined> {
    const idToken = await this.getIDToken(c);
    if (!idToken) {
      await this.logout(c);
      return;
    }
    return this.tokenToPayload(c, idToken);
  }

  /** トークンのペイロードを取得 */
  private async tokenToPayload(
    c: Context,
    token: string | undefined,
  ): Promise<JWTPayload | undefined> {
    const metadata = await this.getIssuerMetadataOf(c, token);
    if (!metadata) {
      return;
    }
    let idToken = token;
    let payload = undefined;
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
        }
      }
    }

    // 数回試しても取得できなかった→無効なリフレッシュトークンとみなす
    // トークン無効化処理
    await this.logout(c);
  }

  /** ログアウト用ハンドラ */
  public logoutHandler<
    R extends HandlerResponse<any>,
    T extends Handler<any, any, any, R>,
  >(callback: T): (c: Context, next: Next) => Promise<R> {
    return async (c: Context, next: Next) => {
      await this.logout(c);
      return callback(c, next);
    };
  }

  /** ログイン用ハンドラ */
  public loginHandler(
    iss: MustIssuer<Issuer>,
    callback: (
      c: Context,
      res:
        | { payload: JWTPayload; error?: undefined }
        | { error: OIDCError; payload?: undefined },
    ) => Promise<HandlerResponse<any>> | HandlerResponse<any>,
  ): (
    c: Context,
  ) => Promise<Response | TypedResponse<any, StatusCode, string>> {
    return async (c: Context) => {
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
        if (!tokenData.id_token) {
          return callback(c, { error: "OAuthServerError" });
        }
        if (tokenData.refresh_token) {
          await this.setRefreshToken(c, `${tokenData.refresh_token}`);
        }
        token = `${tokenData.id_token}`;
      } else {
        token = await this.getIDToken(c);
      }

      // ID Token の検証
      const payload = await this.tokenToPayload(c, token);
      if (!payload) {
        // 有効なrefresh_tokenもないということ
        // ユーザーのアクセスによるログイン開始と見なす
        const authUrl = new URL(metadata.auth_endpoint);
        authUrl.searchParams.append("response_type", "code");
        authUrl.searchParams.append("client_id", metadata.client_id);
        authUrl.searchParams.append("redirect_uri", redirect_uri);
        authUrl.searchParams.append("scope", "openid");
        if (
          metadata.auth_endpoint ===
          "https://accounts.google.com/o/oauth2/v2/auth"
        ) {
          authUrl.searchParams.append("access_type", "offline");
          authUrl.searchParams.append("prompt", "consent");
        }
        return c.redirect(authUrl.toString());
      }
      return callback(c, { payload });
    };
  }
}
