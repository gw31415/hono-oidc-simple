import type { Context } from "hono";
import type { Handler, HandlerResponse, Next, TypedResponse } from "hono/types";
import type { StatusCode } from "hono/utils/http-status";

/** 認証エラーの種類 */
export type OidcError = "OAuthServerError" | "Unauthorized";

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
export abstract class Oidc<
  Issuer extends string | unknown = unknown,
  Payload = any,
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
      payload: Payload;
    } | null,
  ): Promise<void>;

  /** アクセストークンからIssuer URLを取得 */
  protected abstract getIssuerFromToken(
    c: Context,
    token: string | undefined,
  ): Promise<MustIssuer<Issuer> | undefined>;
  /** トークンをペイロードに変換 */
  protected abstract getPayloadFromToken(
    c: Context,
    token: string | undefined,
  ): Promise<Payload | undefined>;

  /** トークン無効化・ログアウト処理 */
  private async logout(c: Context): Promise<void> {
    const accessToken = await this.getIDToken(c);
    if (accessToken) {
      const iss = await this.getIssuerFromToken(c, accessToken);
      const metadata =
        iss === undefined ? undefined : await this.getIssuerMetadata(c, iss);
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
    await this.setRefreshToken(c, null);
    await this.setIDToken(c, null);
  }

  /** 現在のトークンを検証しペイロードを取得 */
  public async getPayload(c: Context): Promise<Payload | undefined> {
    const idToken = await this.getIDToken(c);
    if (!idToken) {
      await this.logout(c);
      return;
    }
    return this.getPayloadFromToken(c, idToken);
  }

  /** ログアウト用ハンドラ */
  public logoutHandler<
    R extends HandlerResponse<any>,
    T extends Handler<any, any, any, R>,
  >(callback: T) {
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
        | { payload: Payload; error?: undefined }
        | { error: OidcError; payload?: undefined },
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
      const payload = await this.getPayloadFromToken(c, token);
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
