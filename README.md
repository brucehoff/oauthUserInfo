This app shows what is returned by Synapse OIDC services:


It is configured to be run as a Google AppEngine application.  To deploy:
- create an OAuth client
- enter the client ID and secret in `src/main/resources/global.properties`
- customize Auth.getRedirectBackUrl() as needed
- after pushing to GitHub, the app' will be deployed
