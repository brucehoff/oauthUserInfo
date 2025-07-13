This app shows what is returned by Synapse OIDC services:


It is configured to be run as a Google AppEngine application.  To deploy:
- create an OAuth client
- enter the client ID and secret in `src/main/resources/global.properties`
- customize Auth.getRedirectBackUrl() as needed


Enable GitHub workflows to deplploy.  From

https://cloud.google.com/blog/products/identity-security/enabling-keyless-authentication-from-github-actions

```
gcloud iam workload-identity-pools create "identity-pool" \
  --project=oauthuserinfo \
  --location="global" \
  --display-name="Identity Pool"


gcloud iam workload-identity-pools providers create-oidc "oidc-provider" \
  --project=oauthuserinfo \
  --location="global" \
  --workload-identity-pool="identity-pool" \
  --display-name="OIDC Provider" \
  --attribute-mapping="google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.aud=assertion.aud" \
  --attribute-condition="assertion.repository_owner=='brucehoff'" \
  --issuer-uri="https://token.actions.githubusercontent.com"



gcloud iam service-accounts add-iam-policy-binding "oauthuserinfo@appspot.gserviceaccount.com" \
  --project="oauthuserinfo" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/1043833862392/locations/global/workloadIdentityPools/identity-pool/attribute.repository/brucehoff/oauthuserinfo"
```


- after pushing to GitHub, the app' will be deployed
