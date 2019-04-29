# identity-outbound-auth-cognito

**Supported Identity Server versions : above 5.7.0**

## How to setup
- Copy the org.wso2.carbon.identity.application.authenticator.cognito-<version-number>.jar to IS_HOME/repository/components/dropins/

- Add the following configuration in IS_HOME/repository/conf/identity/application-authentication.xml

        <AuthenticatorConfig name="CognitoOIDCAuthenticator" enabled="true">
            <Parameter name="ClaimDialectUri">http://wso2.org/oidc/claim</Parameter>
            <Parameter name="CognitoAuthzEndpoint">/oauth2/authorize</Parameter>
            <Parameter name="CognitoTokenEndpoint">/oauth2/token</ParSeameter>
            <Parameter name="CognitoUserInfoEndpoint">/oauth2/userInfo</Parameter>
            <Parameter name="CognitoLogoutEndpoint">/logout</Parameter>
        </AuthenticatorConfig>
        
Note : These configurations are hardcoded in the Authenticator. If the configurations are not present these will taken as default

* Restart the IS server

## Setting up Cognito User pool
- In the App client setting of the App integration of the user pool provide the following
    - Callback URL(s) : https://<is_host>:<is_port>/commonauth
    - Sign out URL(s) : https://<is_host>:<is_port>/commonauth?state=logout
    
Note : It is mandatory to have the state=logout added as the query parameter of the sign out url

## Setting up Identity Provider in the Identity Server
- Click on create Identity Provider
- In the 'Federated Authenticators' section 'AWS Cognito Configuration' provide the following information
    - Client Id and Client Secret of Cognito User pool (You can get these values from App client setting of Cognito User pool)
    - User Pool Domain of Cognito User pool (You can get this value from Domain name setting of Cognito User pool)
    - Callback URL(s) : https://<is_host>:<is_port>/commonauth
    - Sign out URL(s) : https://<is_host>:<is_port>/commonauth?state=logout
    - Add any additional query parameters if required 
- Tick Enable for the AWS Cognito authenticator

## Setting up Service Provider in the Identity Server
- In the 'Local & Outbound Authentication Configuration' of the service provider add the created identity provider as federated authenticator
