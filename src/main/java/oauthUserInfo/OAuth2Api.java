package oauthUserInfo;


import org.apache.commons.codec.binary.Base64;
import org.json.JSONException;
import org.json.JSONObject;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.exceptions.OAuthException;
import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.model.OAuthConfig;
import org.scribe.model.OAuthConstants;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuth20ServiceImpl;
import org.scribe.oauth.OAuthService;
import org.scribe.utils.OAuthEncoder;
import org.scribe.utils.Preconditions;



/**
 * Google OAuth2.0 
 * Released under the same license as scribe (MIT License)
 * @author yincrash
 * 
 * @see <a href="https://gist.githubusercontent.com/yincrash/2465453/raw/9d4eb3149ff8c0eba0316a29d4598949975ac6f5/Google2APi.java">Original Google2Apis</a>
 * 
 * 
 */
public class OAuth2Api extends DefaultApi20 {
	private static String ACCESS_TOKEN_TAG = "access_token";
	private static String ID_TOKEN_TAG = "id_token";
	private static String REFRESH_TOKEN_TAG = "refresh_token";
	private static String ERROR_TAG = "error";

	private String authorizationEndpoint;
	private String accessTokenEndpoint;

	public OAuth2Api(String authorizationEndpoint, String accessTokenEndpoint) {
		this.authorizationEndpoint=authorizationEndpoint;
		this.accessTokenEndpoint=accessTokenEndpoint;		
	}

	@Override
	public String getAccessTokenEndpoint() {
		return accessTokenEndpoint;
	}

	@Override
	public AccessTokenExtractor getAccessTokenExtractor() {
		return new AccessTokenExtractor() {

			public Token extract(String response) {
				Preconditions.checkEmptyString(response, "Response body is incorrect. Can't extract a token from an empty string");
				try {
					JSONObject json = new JSONObject(response);
					if (json.has(ACCESS_TOKEN_TAG)) {
						String token = OAuthEncoder.decode(json.getString(ACCESS_TOKEN_TAG));
						return new Token(token, "", response);
					} else if (json.has(ERROR_TAG)) {
						throw new OAuthException(json.getString(ERROR_TAG));
					} else {
						throw new OAuthException("Response body is incorrect. Can't parse: '" + response + "'", null);
					}
				} catch (JSONException e) {
					throw new RuntimeException(e);
				}
			}
		};
	}

	public AccessTokenExtractor getTokenResponseExtractor() {
		return new AccessTokenExtractor() {

			public Token extract(String response) {
				Preconditions.checkEmptyString(response, "Response body is incorrect. Can't extract a token from an empty string");
				try {
					String accessToken=null;
					String idToken=null;
					String refreshToken=null;
					JSONObject json = new JSONObject(response);
					if (json.has(ACCESS_TOKEN_TAG)) {
						accessToken = OAuthEncoder.decode(json.getString(ACCESS_TOKEN_TAG));
					} else if (json.has(ERROR_TAG)) {
						throw new OAuthException(json.getString(ERROR_TAG));
					} else {
						throw new OAuthException("Response body is incorrect. Can't parse: '" + response + "'", null);
					}
					if (json.has(ID_TOKEN_TAG)) {
						idToken = OAuthEncoder.decode(json.getString(ID_TOKEN_TAG));
					}
					if (json.has(REFRESH_TOKEN_TAG)) {
						refreshToken = OAuthEncoder.decode(json.getString(REFRESH_TOKEN_TAG));
					}          			
					return new TokenResponse(accessToken, idToken, refreshToken, response);
				} catch (JSONException e) {
					throw new RuntimeException(e);
				}
			}
		};
	}

	@Override
	public String getAuthorizationUrl(OAuthConfig config) {
		// Append scope if present
		if (config.hasScope()) {
			String scopedAuthorizationUrl = authorizationEndpoint + "&scope=%s";
			return String.format(scopedAuthorizationUrl, config.getApiKey(),
					OAuthEncoder.encode(config.getCallback()),
					OAuthEncoder.encode(config.getScope()));
		} else {
			return String.format(authorizationEndpoint, config.getApiKey(),
					OAuthEncoder.encode(config.getCallback()));
		}
	}

	@Override
	public Verb getAccessTokenVerb() {
		return Verb.POST;
	}

	@Override
	public OAuthService createService(OAuthConfig config) {
		return new BasicOAuth2Service(this, config);
	}

	public class BasicOAuth2Service extends OAuth20ServiceImpl {

		private static final String REFRESH_TOKEN = "refresh_token";

		private static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
		private static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
		private static final String GRANT_TYPE = "grant_type";
		private DefaultApi20 api;
		private OAuthConfig config;

		public BasicOAuth2Service(DefaultApi20 api, OAuthConfig config) {
			super(api, config);
			this.api = api;
			this.config = config;
		}

		private void addClientAuth(OAuthRequest request) {
			switch (api.getAccessTokenVerb()) {
			case POST:
				request.addBodyParameter(OAuthConstants.CLIENT_ID, config.getApiKey());
				request.addBodyParameter(OAuthConstants.CLIENT_SECRET, config.getApiSecret());
				break;
			case GET:
			default:
				String s = config.getApiKey()+":"+config.getApiSecret();
				String h = "Basic "+Base64.encodeBase64String(s.getBytes());
				request.addHeader("Authorization", h);    	
				//                request.addQuerystringParameter(OAuthConstants.CLIENT_ID, config.getApiKey());
				//                request.addQuerystringParameter(OAuthConstants.CLIENT_SECRET, config.getApiSecret());
			}
		}

		private Response getTokenResponseForAuthorizationCode(Verifier verifier) {
			OAuthRequest request = new OAuthRequest(api.getAccessTokenVerb(), api.getAccessTokenEndpoint());
			addClientAuth(request);
			switch (api.getAccessTokenVerb()) {
			case POST:
				request.addBodyParameter(OAuthConstants.CODE, verifier.getValue());
				if (config.getCallback()!=null) request.addBodyParameter(OAuthConstants.REDIRECT_URI, config.getCallback());
				request.addBodyParameter(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
				break;
			case GET:
			default:
				request.addQuerystringParameter(OAuthConstants.CODE, verifier.getValue());
				if (config.getCallback()!=null) request.addQuerystringParameter(OAuthConstants.REDIRECT_URI, config.getCallback());
				if(config.hasScope()) request.addQuerystringParameter(OAuthConstants.SCOPE, config.getScope());
			}
			return request.send();
		}

		@Override
		public Token getAccessToken(Token requestToken, Verifier verifier) {
			Response response = getTokenResponseForAuthorizationCode(verifier);
			return api.getAccessTokenExtractor().extract(response.getBody());
		}

		public TokenResponse getTokenResponse(Token requestToken, Verifier verifier) {
			Response response = getTokenResponseForAuthorizationCode(verifier);
			return (TokenResponse)((OAuth2Api)api).getTokenResponseExtractor().extract(response.getBody());
		}

		private Response getTokenResponseForRefreshTokenIntern(Verifier verifier) {
			OAuthRequest request = new OAuthRequest(api.getAccessTokenVerb(), api.getAccessTokenEndpoint());
			addClientAuth(request);
			switch (api.getAccessTokenVerb()) {
			case POST:
				request.addBodyParameter(REFRESH_TOKEN, verifier.getValue());
				request.addBodyParameter(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
				break;
			case GET:
			default:
				request.addQuerystringParameter(REFRESH_TOKEN, verifier.getValue());
				request.addQuerystringParameter(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
			}
			return request.send();
		}

		public TokenResponse getTokenResponseForRefreshToken(Token requestToken, Verifier verifier) {
			Response response = getTokenResponseForRefreshTokenIntern(verifier);
			return (TokenResponse)((OAuth2Api)api).getTokenResponseExtractor().extract(response.getBody());
		}
	}

}
