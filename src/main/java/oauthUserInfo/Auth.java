
package oauthUserInfo;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.json.JSONObject;
import org.scribe.model.OAuthConfig;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithWebIdentityRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithWebIdentityResult;
import com.amazonaws.services.securitytoken.model.Credentials;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;


public class Auth extends HttpServlet {
	private static Logger logger = Logger.getLogger("Auth");

	private static final String REQUIRED_SYNAPSE_TEAM_ID = "273957";
//	private static final String CLAIMS = "{\"team\":{\"values\":[\""+REQUIRED_SYNAPSE_TEAM_ID+"\"]},"
//			+ "\"userid\":{\"essential\":true}}";
	
//	private static final String CLAIMS = "{\"team\":{\"values\":[\"3329051\"]},"
//			+ "\"user_name\":{\"essential\":true},"
//			+ "\"family_name\":{\"essential\":true},"
//			+ "\"given_name\":{\"essential\":true},"
//			+ "\"email\":{\"essential\":true},"
//			+ "\"email_verified\":{\"essential\":true},"
//			+ "\"userid\":{\"essential\":true},"
//			+ "\"orcid\":{\"essential\":true},"
//			+ "\"is_certified\":{\"essential\":true},"
//			+ "\"is_validated\":{\"essential\":true},"
//			+ "\"validated_given_name\":{\"essential\":true},"
//			+ "\"validated_family_name\":{\"essential\":true},"
//			+ "\"validated_location\":{\"essential\":true},"
//			+ "\"validated_email\":{\"essential\":true},"
//			+ "\"validated_company\":{\"essential\":true},"
//			+ "\"validated_at\":{\"essential\":true},"
//			+ "\"validated_orcid\":{\"essential\":true},"
//			+ "\"company\":{\"essential\":false}}";	
	
	private static final String CLAIMS = "{"
					+"\"ga4gh_passport_v1\":{\"values\":[\"https://repo-prod.prod.sagebase.org/repo/v1/accessRequirement/12345\"]},"
					+ "\"email\":{\"essential\":true},"
					+ "\"userid\":{\"essential\":true}}";
	
    private static final String AUTHORIZE_URL_SYNAPSE = 
    		"https://signin.synapse.org?client_id=%s&redirect_uri=%s&"+
    		"claims={\"id_token\":"+CLAIMS+",\"userinfo\":"+CLAIMS+"}";
    private static final String AUTHORIZE_URL_SYNAPSE_STAGING = 
    		"https://staging-signin.synapse.org?client_id=%s&redirect_uri=%s&"+
    		"claims={\"id_token\":"+CLAIMS+",\"userinfo\":"+CLAIMS+"}";
    private static final String TOKEN_URL_SYNAPSE = "https://repo-prod.prod.sagebase.org/auth/v1/oauth2/token";
    private static final String TOKEN_URL_SYNAPSE_STAGING = "https://repo-staging.prod.sagebase.org/auth/v1/oauth2/token";

    private static final String AUTHORIZE_URL_GOOGLE = "https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=%s&redirect_uri=%s";
    private static final String TOKEN_URL_GOOGLE = "https://accounts.google.com/o/oauth2/token";

	private static final String AUTHORIZE_URL_ORCID = "https://orcid.org/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s";
	private static final String TOKEN_URL_ORCID = "https://pub.orcid.org/oauth/token";

	private static final String SYNAPSE_OAUTH_USER_INFO_API_URL = "https://repo-prod.prod.sagebase.org/auth/v1/oauth2/userinfo";
	private static final String SYNAPSE_STAGING_OAUTH_USER_INFO_API_URL = "https://repo-staging.prod.sagebase.org/auth/v1/oauth2/userinfo";
	private static final String GOOGLE_OAUTH_USER_INFO_API_URL = "https://www.googleapis.com/oauth2/v2/userinfo";
	private static final String ORCID_OAUTH_USER_INFO_API_URL = "https://orcid.org/oauth/userinfo";
	
	
	private static final String SYNAPSE_OAUTH_REVOCATION_API_URL = "https://repo-prod.prod.sagebase.org/auth/v1/oauth2/revoke";
	private static final String SYNAPSE_STAGING_OAUTH_REVOCATION_API_URL = "https://repo-staging.prod.sagebase.org/auth/v1/oauth2/revoke";
	
	private static final String SYNAPSE_TOKEN_METADATA_URL_PREFIX = "https://repo-prod.prod.sagebase.org/auth/v1/oauth2/token/";
	private static final String SYNAPSE_STAGING_TOKEN_METADATA_URL_PREFIX = "https://repo-staging.prod.sagebase.org/auth/v1/oauth2/token/";
	private static final String SYNAPSE_TOKEN_METADATA_URL_SUFFIX = "/metadata";
	
	private static final String SCOPE_EMAIL = "email";

	@Override
	public void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws IOException {
		try {
			doPostIntern(req, resp);
		} catch (Exception e) {
			logger.log(Level.SEVERE, "", e);
			resp.setContentType("text/plain");
			try (ServletOutputStream os=resp.getOutputStream()) {
				os.println("Error:");
				e.printStackTrace(new PrintStream(os));
			}
			resp.setStatus(500);
		}
	}

	private static final String CLIENT_ENDPOINT = "http://oauthuserinfo.appspot.com/";
	private static final String SYNAPSE_BUTTON_URI = "oauthUserInfoSynapse";
	private static final String SYNAPSE_BUTTON_STAGING_URI = "oauthUserInfoSynapseStaging";
	
	private static final String GOOGLE_BUTTON_URI = "oauthUserInfoGoogle";
	private static final String ORCID_BUTTON_URI = "oauthUserInfoOrcid";
	
	private String getRedirectBackUrlGoogle(HttpServletRequest req) throws MalformedURLException {
		return CLIENT_ENDPOINT+GOOGLE_BUTTON_URI;
	}
	
	private String getRedirectBackUrlSynapse(HttpServletRequest req) throws MalformedURLException {
		return CLIENT_ENDPOINT+SYNAPSE_BUTTON_URI;
	}
	
	private String getRedirectBackUrlSynapseStaging(HttpServletRequest req) throws MalformedURLException {
		return CLIENT_ENDPOINT+SYNAPSE_BUTTON_STAGING_URI;
	}
	
	private String getRedirectBackUrlOrcid(HttpServletRequest req) throws MalformedURLException {
		return CLIENT_ENDPOINT+ORCID_BUTTON_URI;
	}
	
	private static String getClientIdSynapse() {
		String result = getProperty("SYNAPSE_OAUTH_CLIENT_ID");
		logger.log(Level.WARNING, "SYNAPSE_OAUTH_CLIENT_ID="+result);
		return result;
	}
	
	private static String getClientSecretSynapse() {
		String result =  getProperty("SYNAPSE_OAUTH_CLIENT_SECRET");
		logger.log(Level.WARNING, "SYNAPSE_OAUTH_CLIENT_SECRET="+result);
		return result;
	}
	
	private static String getClientIdGoogle() {
		String result = getProperty("GOOGLE_OAUTH_CLIENT_ID");
		logger.log(Level.WARNING, "GOOGLE_OAUTH_CLIENT_ID="+result);
		return result;
	}
	
	private static String getClientSecretGoogle() {
		String result =  getProperty("GOOGLE_OAUTH_CLIENT_SECRET");
		logger.log(Level.WARNING, "GOOGLE_OAUTH_CLIENT_SECRET="+result);
		return result;
	}
	
	private static String getClientIdOrcid() {
		String result = getProperty("ORCID_OAUTH_CLIENT_ID");
		logger.log(Level.WARNING, "ORCID_OAUTH_CLIENT_ID="+result);
		return result;
	}
	
	private static String getClientSecretOrcid() {
		String result =  getProperty("ORCID_OAUTH_CLIENT_SECRET");
		logger.log(Level.WARNING, "ORCID_OAUTH_CLIENT_SECRET="+result);
		return result;
	}
	
	private static boolean forceAuth(String requestURI) {
		return requestURI.contains("ForceAuth");
	}
	
	private static final String FORCE_AUTH_PARAM = "&prompt=login";
	
	private static boolean omitCode(String requestURI) {
		return requestURI.contains("OmitCode");
	}
	
	private static final String RESPONSE_TYPE_PARAM = "&response_type=code";
	
	private void doPostIntern(HttpServletRequest req, HttpServletResponse resp)
			throws IOException {
		if (req.getRequestURI().contains(GOOGLE_BUTTON_URI)) {
			String redirectBackUrl = getRedirectBackUrlGoogle(req);
			String redirectUrl = new OAuth2Api(AUTHORIZE_URL_GOOGLE, TOKEN_URL_GOOGLE).
					getAuthorizationUrl(new OAuthConfig(getClientIdGoogle(), null, redirectBackUrl, null, SCOPE_EMAIL, null));
			resp.setHeader("Location", redirectUrl+"&state=someRandomStateToPassThrough");
			resp.setStatus(307);
		} else if (req.getRequestURI().contains(ORCID_BUTTON_URI)) {
			String redirectBackUrl = getRedirectBackUrlOrcid(req);
			String redirectUrl = new OAuth2Api(AUTHORIZE_URL_ORCID, TOKEN_URL_ORCID).
					getAuthorizationUrl(new OAuthConfig(getClientIdOrcid(), null, redirectBackUrl, null, "openid", null));
			resp.setHeader("Location", redirectUrl+"&state=someRandomStateToPassThrough");
			resp.setStatus(303);
		} else if (req.getRequestURI().contains(SYNAPSE_BUTTON_STAGING_URI)) {
			String redirectBackUrl = getRedirectBackUrlSynapseStaging(req);
			String authorizeURL = AUTHORIZE_URL_SYNAPSE_STAGING;
			if (forceAuth(req.getRequestURI())) authorizeURL += FORCE_AUTH_PARAM;
			if (!omitCode(req.getRequestURI())) authorizeURL += RESPONSE_TYPE_PARAM;
			String redirectUrl = new OAuth2Api(authorizeURL, TOKEN_URL_SYNAPSE_STAGING).
					getAuthorizationUrl(new OAuthConfig(getClientIdSynapse(), null, redirectBackUrl, null, "openid view download authorize offline_access", null));
			resp.setHeader("Location", redirectUrl+"&state=someRandomStateToPassThrough");
			resp.setStatus(303);
		} else if (req.getRequestURI().contains(SYNAPSE_BUTTON_URI)) { // note, this must go after SYNAPSE_BUTTON_STAGING_URI since it's a substring!
			String redirectBackUrl = getRedirectBackUrlSynapse(req);
			String authorizeURL = AUTHORIZE_URL_SYNAPSE;
			if (forceAuth(req.getRequestURI())) authorizeURL += FORCE_AUTH_PARAM;
			if (!omitCode(req.getRequestURI())) authorizeURL += RESPONSE_TYPE_PARAM;
			String redirectUrl = new OAuth2Api(authorizeURL, TOKEN_URL_SYNAPSE).
					getAuthorizationUrl(new OAuthConfig(getClientIdSynapse(), null, redirectBackUrl, null, "openid view download authorize offline_access", null));
			resp.setHeader("Location", redirectUrl+"&state=someRandomStateToPassThrough");
			resp.setStatus(303);
		} else {
			throw new RuntimeException("Unexpected URI "+req.getRequestURI());
		}
	}

	@Override
	public void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws IOException {
		try {
			doGetIntern(req, resp);
		} catch (Exception e) {
			logger.log(Level.SEVERE, "", e);
			resp.setContentType("text/plain");
			try (ServletOutputStream os=resp.getOutputStream()) {
				os.println("Error:");
				e.printStackTrace(new PrintStream(os));
			}
			resp.setStatus(500);
		}
	}
	
	// from https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html#STSConsoleLink_programJava
	private String getConsoleLoginURL(Credentials federatedCredentials) throws IOException {

		// The issuer parameter specifies your internal sign-in
		// page, for example https://mysignin.internal.mycompany.com/.
		// The console parameter specifies the URL to the destination console of the
		// AWS Management Console. This example goes to Amazon SNS. 
		// The signin parameter is the URL to send the request to.

		String issuerURL = CLIENT_ENDPOINT;
		String consoleURL = "https://console.aws.amazon.com/servicecatalog";
		String signInURL = "https://signin.aws.amazon.com/federation";
		  
		// Create the sign-in token using temporary credentials,
		// including the access key ID,  secret access key, and security token.
		String sessionJson = String.format(
		  "{\"%1$s\":\"%2$s\",\"%3$s\":\"%4$s\",\"%5$s\":\"%6$s\"}",
		  "sessionId", federatedCredentials.getAccessKeyId(),
		  "sessionKey", federatedCredentials.getSecretAccessKey(),
		  "sessionToken", federatedCredentials.getSessionToken());
		              
		// Construct the sign-in request with the request sign-in token action, a
		// 12-hour console session duration, and the JSON document with temporary 
		// credentials as parameters.

		String getSigninTokenURL = signInURL + 
		                           "?Action=getSigninToken" +
		                           "&DurationSeconds=43200" + 
		                           "&SessionType=json&Session=" + 
		                           URLEncoder.encode(sessionJson,"UTF-8");

		URL url = new URL(getSigninTokenURL);

		// Send the request to the AWS federation endpoint to get the sign-in token
		URLConnection conn = url.openConnection();

		BufferedReader bufferReader = new BufferedReader(new 
		  InputStreamReader(conn.getInputStream()));  
		String returnContent = bufferReader.readLine();

		String signinToken = new JSONObject(returnContent).getString("SigninToken");

		String signinTokenParameter = "&SigninToken=" + URLEncoder.encode(signinToken,"UTF-8");

		// The issuer parameter is optional, but recommended. Use it to direct users
		// to your sign-in page when their session expires.

		String issuerParameter = "&Issuer=" + URLEncoder.encode(issuerURL, "UTF-8");

		// Finally, present the completed URL for the AWS console session to the user

		String destinationParameter = "&Destination=" + URLEncoder.encode(consoleURL,"UTF-8");
		String loginURL = signInURL + "?Action=login" +
		                     signinTokenParameter + issuerParameter + destinationParameter;	
		return loginURL;
	}
	
	public static Jwt<Header,Claims> parseJWT(String token) {
		// Note, we don't check the signature
		String[] pieces = token.split("\\.");
		if (pieces.length!=3) throw new IllegalArgumentException("Expected three sections of the token but found "+pieces.length);
		String unsignedToken = pieces[0]+"."+pieces[1]+".";
		return Jwts.parser().parseClaimsJwt(unsignedToken);
	}
	
	public static String getRefreshTokenID(String accessToken) {
		Jwt<Header,Claims> jwt = parseJWT(accessToken);
		return (String)jwt.getBody().get("refresh_token_id");
	}
		
	private void doGetIntern(HttpServletRequest req, HttpServletResponse resp)
				throws Exception {
		
		OAuth2Api.BasicOAuth2Service service = null;
		OAuthRequest request = null;
		String result = null;
		Claims idTokenClaims = null;
		TokenResponse tokenResponse = null;
		String tokenMetadata = null;
		Response response = null;
		String capturedAccessToken = null;
		if (StringUtils.isNotEmpty(req.getParameter("error"))) {
			resp.setContentType("text/plain");
			try (ServletOutputStream os=resp.getOutputStream()) {
				os.println();
				os.println("error:");
				os.println(req.getParameter("error"));
				
				os.println();
			}
			resp.setStatus(200);
			return;
		}
		if (req.getRequestURI().contains(GOOGLE_BUTTON_URI)) {
			service = (OAuth2Api.BasicOAuth2Service)(new OAuth2Api(AUTHORIZE_URL_GOOGLE, TOKEN_URL_GOOGLE)).
					createService(new OAuthConfig(getClientIdGoogle(), getClientSecretGoogle(), getRedirectBackUrlGoogle(req), null, null, null));
			request = new OAuthRequest(Verb.GET, GOOGLE_OAUTH_USER_INFO_API_URL);
			String authorizationCode = req.getParameter("code");
			Token accessToken = service.getAccessToken(null, new Verifier(authorizationCode));
			// Use the access token to get the UserInfo from Google.
			service.signRequest(accessToken, request);
			response = request.send();
			if(!response.isSuccessful()){
				throw new Exception("Response code: "+response.getCode()+" Message: "+response.getMessage());
			}
			
			result = response.getBody();
		} else if (req.getRequestURI().contains(ORCID_BUTTON_URI)) {
			service = (OAuth2Api.BasicOAuth2Service)(new OAuth2Api(AUTHORIZE_URL_ORCID, TOKEN_URL_ORCID)).
					createService(new OAuthConfig(getClientIdOrcid(), getClientSecretOrcid(), getRedirectBackUrlOrcid(req), null, null, null));
			request = new OAuthRequest(Verb.GET, ORCID_OAUTH_USER_INFO_API_URL);
			String authorizationCode = req.getParameter("code");
			Token accessToken = service.getAccessToken(null, new Verifier(authorizationCode));
			result = accessToken.getRawResponse();
		} else if (false && req.getRequestURI().contains(SYNAPSE_BUTTON_URI)) {
			service = (OAuth2Api.BasicOAuth2Service)(new OAuth2Api(AUTHORIZE_URL_SYNAPSE, TOKEN_URL_SYNAPSE)).
					createService(new OAuthConfig(getClientIdSynapse(), getClientSecretSynapse(), getRedirectBackUrlSynapse(req), null, null, null));
			String authorizationCode = req.getParameter("code");
			tokenResponse = service.getTokenResponse(null, new Verifier(authorizationCode));
			
			// parse ID Token
			Jwt<Header,Claims> jwt = parseJWT(tokenResponse.getIdToken());
			String synapseUserId = jwt.getBody().get("userid", String.class);
			// check if a member of 273957.  If not, don't proceed
			List<String> teamIds = jwt.getBody().get("team", List.class);
			boolean isInDesignatedTeam = (teamIds!=null && teamIds.contains(REQUIRED_SYNAPSE_TEAM_ID));
			
			if (isInDesignatedTeam) {
				// get STS token
				AssumeRoleWithWebIdentityRequest assumeRoleWithWebIdentityRequest = new AssumeRoleWithWebIdentityRequest();
				assumeRoleWithWebIdentityRequest.setWebIdentityToken(tokenResponse.getIdToken());
				assumeRoleWithWebIdentityRequest.setRoleArn("arn:aws:iam::563295687221:role/Service_Catalog_Role");
				assumeRoleWithWebIdentityRequest.setRoleSessionName(synapseUserId);
				AWSSecurityTokenService stsClient = AWSSecurityTokenServiceClientBuilder.standard().withRegion(Regions.US_EAST_1)
						.withCredentials(new AWSCredentialsProvider() {
							@Override
							public AWSCredentials getCredentials() {
								return new AWSCredentials() {
									@Override
									public String getAWSAccessKeyId() {
										return "dummyKeyId";
									}
									@Override
									public String getAWSSecretKey() {
										return "dummySecret";
									}};
							}
							@Override
							public void refresh() {}}).build();
				
				// TODO pass tags https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
				AssumeRoleWithWebIdentityResult assumeRoleWithWebIdentityResult = stsClient.assumeRoleWithWebIdentity(assumeRoleWithWebIdentityRequest);
				Credentials credentials = assumeRoleWithWebIdentityResult.getCredentials();
				logger.log(Level.INFO, credentials.toString());
				// redirect to AWS login
				String redirectURL = getConsoleLoginURL(credentials);
				
				resp.setHeader("Location", redirectURL);
				resp.setStatus(302);
			} else {
				resp.setContentType("text/plain");
				try (ServletOutputStream os=resp.getOutputStream()) {
					os.println("To proceed you must be a member of team "+REQUIRED_SYNAPSE_TEAM_ID);
				}
				resp.setStatus(200);
			}
			return;
		} else if (req.getRequestURI().contains(SYNAPSE_BUTTON_STAGING_URI) || req.getRequestURI().contains(SYNAPSE_BUTTON_URI)) {
			String authorizeURL=null;
			String tokenURL=null;
			String redirectBackUrl=null;
			String userInfoEndpoint=null;
			String revocationUrl=null;
			String tokenMetaDataPrefix=null;
			if (req.getRequestURI().contains(SYNAPSE_BUTTON_STAGING_URI)) {
				authorizeURL = AUTHORIZE_URL_SYNAPSE_STAGING;
				tokenURL=TOKEN_URL_SYNAPSE_STAGING;
				redirectBackUrl=getRedirectBackUrlSynapseStaging(req);
				userInfoEndpoint=SYNAPSE_STAGING_OAUTH_USER_INFO_API_URL;
				revocationUrl=SYNAPSE_STAGING_OAUTH_REVOCATION_API_URL;
				tokenMetaDataPrefix = SYNAPSE_STAGING_TOKEN_METADATA_URL_PREFIX;
			} else {
				authorizeURL = AUTHORIZE_URL_SYNAPSE;
				tokenURL=TOKEN_URL_SYNAPSE;
				redirectBackUrl=getRedirectBackUrlSynapse(req);
				userInfoEndpoint=SYNAPSE_OAUTH_USER_INFO_API_URL;
				revocationUrl=SYNAPSE_OAUTH_REVOCATION_API_URL;
				tokenMetaDataPrefix = SYNAPSE_TOKEN_METADATA_URL_PREFIX;
			}
			service = (OAuth2Api.BasicOAuth2Service)(new OAuth2Api(authorizeURL, tokenURL)).
					createService(new OAuthConfig(getClientIdSynapse(), getClientSecretSynapse(), redirectBackUrl, null, null, null));
			String authorizationCode = req.getParameter("code");
			tokenResponse = service.getTokenResponse(null, new Verifier(authorizationCode));
			String accessToken = tokenResponse.getToken();
			String refreshTokenId = getRefreshTokenID(accessToken);
			String refreshToken = tokenResponse.getRefreshToken();
			String idToken = tokenResponse.getIdToken();
			Jwt<Header,Claims> idTokenJwt = parseJWT(idToken);
			idTokenClaims = idTokenJwt.getBody();
			
			// use the refresh token to get a new access token
			TokenResponse tokenResponse2 = service.getTokenResponseForRefreshToken(null, new Verifier(refreshToken));
			
			// verify that access token has changed
			if (accessToken.equals(tokenResponse2.getToken())) 
				throw new RuntimeException("Access token has not changed");
			if (!refreshTokenId.equals(getRefreshTokenID(tokenResponse2.getToken()))) {
				throw new RuntimeException("access tokens have different refresh token IDs.");
			}
			// verify that refresh token has changed
			if (refreshToken.equals(tokenResponse2.getIdToken())) {
				throw new RuntimeException("refresh token has not changed");
			}
			
			// verify that previous refresh token does not work
			try {
				service.getTokenResponseForRefreshToken(null, new Verifier(refreshToken));
				throw new RuntimeException("Previous refresh token still works but should not!");
			} catch (Exception e) {
				// as expected
			}
			
			// verify that original access token still works
			request = new OAuthRequest(Verb.GET, userInfoEndpoint);
			request.addHeader("Authorization", "Bearer "+accessToken);
			response = request.send();
			if(!response.isSuccessful()){
				throw new RuntimeException("Response code: "+response.getCode()+" Message: "+response.getMessage());
			}
			result = response.getBody();
			
			// get refresh token metadata
			request = new OAuthRequest(Verb.GET, tokenMetaDataPrefix+refreshTokenId+SYNAPSE_TOKEN_METADATA_URL_SUFFIX);
			String s = getClientIdSynapse()+":"+getClientSecretSynapse();
			request.addHeader("Authorization", "Basic "+Base64.encodeBase64String(s.getBytes()));
			response = request.send();
			if(!response.isSuccessful()){
				throw new RuntimeException("Response code: "+response.getCode()+" Message: "+response.getMessage());
			}
			tokenMetadata = response.getBody();
			
//			// revoke refresh token and access tokens
//			request = new OAuthRequest(Verb.POST, revocationUrl);
//			request.addHeader("Authorization", "Basic "+Base64.encodeBase64String(s.getBytes()));
//			request.addHeader("Content-Type", "application/json");
//			JSONObject revocationPayload = new JSONObject();
//			revocationPayload.put("token", tokenResponse2.getRefreshToken());
//			revocationPayload.put("token_type_hint", "refresh_token");
//			request.addPayload(revocationPayload.toString());
//			response = request.send();
//			if (!response.isSuccessful()) {
//				throw new RuntimeException("Revocation failed.  Response code: "+response.getCode()+" Message: "+response.getMessage());
//			}
//			
//			// try to use last access token, verifying that it doesn't work
//			request = new OAuthRequest(Verb.GET, userInfoEndpoint);
//			request.addHeader("Authorization", "Bearer "+accessToken);
//			response = request.send();
//			if(response.isSuccessful()){
//				throw new RuntimeException("Access token should not work but does!");
//			}
			capturedAccessToken=accessToken;
		} else {
			throw new RuntimeException("Unexpected URI "+req.getRequestURI());
		}
		JSONObject json = new JSONObject(result);
		logger.log(Level.WARNING, result);
		resp.setContentType("text/plain");
		try (ServletOutputStream os=resp.getOutputStream()) {
			os.println("id_token:");
			for (String key: idTokenClaims.keySet()) {
				os.println(key+" "+idTokenClaims.get(key));
			}
			os.println("\nUserinfo:");
			for (String key: json.keySet()) {
				os.println(key+" "+json.get(key));
			}
			os.println();
//			os.println("Refresh token metadata:");
//			os.println(tokenMetadata);
			
//			os.println();
//			os.println("access token: "+capturedAccessToken);
//			os.println("Response from attempting to use revoked access token:");
//			os.println(""+response.getCode());
//			os.println(response.getBody());
		}
		resp.setStatus(200);
	}
	
	
	private static Properties properties = null;

	public static void initProperties() {
		if (properties!=null) return;
		properties = new Properties();
		InputStream is = null;
		try {
			is = Auth.class.getClassLoader().getResourceAsStream("global.properties");
			properties.load(is);
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
			if (is!=null) try {
				is.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
	}

	public static String getProperty(String key) {
		return getProperty(key, true);
	}
	
	private static boolean missing(String s) {
		return StringUtils.isEmpty(s) || "null".equals(s);
	}

	public static String getProperty(String key, boolean required) {
		initProperties();
		{
			String embeddedProperty = properties.getProperty(key);
			if (!missing(embeddedProperty)) return embeddedProperty;
		}
		{
			String environmentVariable = System.getenv(key);
			if (!missing(environmentVariable)) return environmentVariable;
		}
		{
			String commandlineOption = System.getProperty(key);
			if (!missing(commandlineOption)) return commandlineOption;
		}
		if (required) throw new RuntimeException("Cannot find value for "+key);
		return null;
	}

}
