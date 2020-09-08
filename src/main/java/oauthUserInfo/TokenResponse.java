package oauthUserInfo;

import org.scribe.model.Token;

public class TokenResponse extends Token {
	String idToken;
	String refreshToken;

	public TokenResponse(String accessToken, String idToken, String refreshToken, String rawResponse) {
		super(accessToken, "", rawResponse);
		this.idToken=idToken;
		this.refreshToken=refreshToken;
	}

	public String getIdToken() {
		return idToken;
	}

	public void setIdToken(String idToken) {
		this.idToken = idToken;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((idToken == null) ? 0 : idToken.hashCode());
		result = prime * result + ((refreshToken == null) ? 0 : refreshToken.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		TokenResponse other = (TokenResponse) obj;
		if (idToken == null) {
			if (other.idToken != null)
				return false;
		} else if (!idToken.equals(other.idToken))
			return false;
		if (refreshToken == null) {
			if (other.refreshToken != null)
				return false;
		} else if (!refreshToken.equals(other.refreshToken))
			return false;
		return true;
	}
	
	

}
