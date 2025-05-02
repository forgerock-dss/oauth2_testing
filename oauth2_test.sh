#!/bin/bash

# Written by Darinder S Shokar - ForgeRock Customer Success
# Script requires the "jq" tool be already installed to function
# Article: https://developer.forgerock.com/docs/platform/how-tos/script-executing-oauth2-authorization-code-flow-pkce-am
# Script Location: https://stash.forgerock.org/users/shokard/repos/oauth2/browse/oauth2_test.sh

# Parameters. Modify as appropriate:
REALM=alpha # For top-level realm use REALM=root
AM_HOST=https://my-am-host.com/am

#Ensure Token Endpoint Authentication Method is set to client_secret_post and NOT client_secret_basic
CLIENT_ID=XXXXXX
# CLIENT_SECRET is not required for a public client but is required for token introspection
CLIENT_SECRET=XXXXXX

#Comment out CLIENT_TYPE as required
CLIENT_TYPE=confidential
#CLIENT_TYPE=public

SCOPES=openid%20profile
REDIRECT_URL=https://httpbin.org/anything
POST_LOGOUT_REDIRECT_URI=https://httpbin.org/anything
USERNAME=demo
PASSWORD=Ch4ng31t
AM_TREE=Login

#Public clients can no longer introspect tokens as a client secret is required.
#To simulate a backend application which needs to introspect the public client access token a new introspect confidential OAuth2 client is created.
#This client is configured to only allow the client_credentials grant_type and has a single scope defined of am-introspect-all-tokens.
#This introspect client is then used to introspect the original public client access token.

INTROSPECT_CLIENT_ID=introspect
INTROSPECT_CLIENT_SECRET=XXXXXX

AM_AUTHENTICATE="$AM_HOST/json/realms/$REALM/authenticate?authIndexType=service&authIndexValue=$AM_TREE"
AM_VALIDATE="$AM_HOST/json/realms/root/realms/$REALM/sessions?_prettyPrint=true&_action=validate"
AM_AUTHORIZE=$AM_HOST/oauth2/realms/$REALM/authorize
AM_ACCESS_TOKEN=$AM_HOST/oauth2/realms/$REALM/access_token
AM_TOKENINFO=$AM_HOST/oauth2/realms/$REALM/tokeninfo
AM_INTROSPECT=$AM_HOST/oauth2/realms/$REALM/introspect
AM_USERINFO=$AM_HOST/oauth2/realms/$REALM/userinfo
AM_ENDSESSION=$AM_HOST/oauth2/realms/root/realms/$REALM/connect/endSession
AM_CHECKSESSION=$AM_HOST/oauth2/connect/checkSession
AM_REVOKE=$AM_HOST/oauth2/realms/root/realms/$REALM/token/revoke
RESPONSE_TYPE=code
VERSION_HEADER='resource=2.0, protocol=1.0'
CONTENT_TYPE='application/json'

# On latent network connections there may be a need to retry, hence the following curl command is used.
CURL='curl -k -s --connect-timeout 1 --max-time 5 --retry 2'

MODE=$1

if [ -z "$1" ]; then
	echo "Execute using ./oauth2_test.sh non-pkce|pkce. For example ./oauth2_test.sh pkce"
	exit 1
fi

jqCheck() {
	hash jq &>/dev/null
	if [ $? -eq 1 ]; then
		echo >&2 "The jq Command-line JSON processor is not installed on the system. Please install and re-run."
		exit 1
	fi
}

getCookieName() {
	echo "Getting cookie name"
	AM_COOKIENAME=$($CURL "$AM_HOST"/json/serverinfo/\* | jq -r .cookieName)
	echo "CookieName is: $AM_COOKIENAME"
}

authN() {
	echo "*********************"
	echo "Authenticating $USERNAME user to generate SSO token"
	SSO_TOKEN=$($CURL --request POST --header "Content-Type: $CONTENT_TYPE" --header "Accept-API-Version: $VERSION_HEADER" --header "X-OpenAM-Username: $USERNAME" --header "X-OpenAM-Password: $PASSWORD" -d '' "$AM_AUTHENTICATE" | jq -r .tokenId)
	echo "SSO Token: $SSO_TOKEN"
	echo ""
	echo "*********************"
}

validateSession() {
	echo "Validating SSO token: $SSO_TOKEN"
	echo ""
	$CURL --request POST --header "Content-Type: $CONTENT_TYPE" --header "Accept-API-Version: $VERSION_HEADER" --Cookie "$AM_COOKIENAME=$SSO_TOKEN" $AM_VALIDATE | jq .
	echo "*********************"
}

gen_PKCEMaterial() {
	if [ $MODE == "pkce" ]; then
		echo "Generating PKCE Verifier"
		VERIFIER=$(LC_CTYPE=C && LANG=C && cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 50 | head -n 1)
		echo "Verifier is: $VERIFIER"
		#Generate PKCE Challenge from Verifier and convert / + = characters"
		CHALLENGE=$(/bin/echo -n $VERIFIER | shasum -a 256 | cut -d " " -f 1 | xxd -r -p | base64 | tr / _ | tr + - | tr -d =)
		echo "Challenge is: $CHALLENGE"
		echo ""
		echo "*********************"
	fi
}

getAuthCode() {
	echo "Getting auth code"
	if [ $MODE == "pkce" ]; then
		AUTH_CODE=$($CURL --request POST --header "Content-Type: application/x-www-form-urlencoded" --Cookie "$AM_COOKIENAME=$SSO_TOKEN" --data "redirect_uri=$REDIRECT_URL&scope=$SCOPES&response_type=$RESPONSE_TYPE&client_id=$CLIENT_ID&csrf=$SSO_TOKEN&decision=allow&code_challenge=$CHALLENGE&code_challenge_method=S256" "$AM_AUTHORIZE" -v --stderr - | grep "code=" | cut -d '=' -f2 | cut -d '&' -f1)
	else
		AUTH_CODE=$($CURL --request POST --header "Content-Type: application/x-www-form-urlencoded" --Cookie "$AM_COOKIENAME=$SSO_TOKEN" --data "redirect_uri=$REDIRECT_URL&scope=$SCOPES&response_type=$RESPONSE_TYPE&client_id=$CLIENT_ID&csrf=$SSO_TOKEN&decision=allow" "$AM_AUTHORIZE" -v --stderr - | grep "code=" | cut -d '=' -f2 | cut -d '&' -f1)
	fi
	echo "Auth code is: $AUTH_CODE"
	echo ""
	echo "*********************"
}

getTokens() {
	echo "Getting access and refresh tokens"
	echo "Using auth code $AUTH_CODE"
	if [ $MODE == "pkce" ] && [ $CLIENT_TYPE == "confidential" ]; then
		#code_verifier parameter added
		TOKENS=$($CURL --request POST --header "Cache-Control: no-cache" --data "grant_type=authorization_code&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&redirect_uri=$REDIRECT_URL&code=$AUTH_CODE&code_verifier=$VERIFIER" "$AM_ACCESS_TOKEN" | jq .)
	elif [ $MODE == "pkce" ] && [ $CLIENT_TYPE == "public" ]; then
		#client_secret parameter removed
		TOKENS=$($CURL --request POST --header "Cache-Control: no-cache" --data "grant_type=authorization_code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URL&code=$AUTH_CODE&code_verifier=$VERIFIER" "$AM_ACCESS_TOKEN" | jq .)
	else
		TOKENS=$($CURL --request POST --header "Cache-Control: no-cache" --data "grant_type=authorization_code&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&redirect_uri=$REDIRECT_URL&code=$AUTH_CODE" "$AM_ACCESS_TOKEN" | jq .)
	fi

	echo $TOKENS | jq .

	ACCESS_TOKEN=$(echo $TOKENS | jq -r .access_token)
	REFRESH_TOKEN=$(echo $TOKENS | jq -r .refresh_token)
	ID_TOKEN=$(echo $TOKENS | jq -r .id_token)

	echo ""
	echo "*********************"
}

hitTokenInfo() {
	echo "Hitting tokeninfo endpoint"
	TOKENINFO=$($CURL "$AM_TOKENINFO?access_token=$ACCESS_TOKEN" | jq .)
	echo $TOKENINFO | jq .
	echo ""
	echo "*********************"
}

decodeJWT() {
	echo "Decoding ${1} token: ${2}"
	jq -R 'split(".") | .[1] | @base64d | fromjson' <<<"${2}"
	echo ""
	echo "*********************"
}

hitIntrospectAccessToken() {
	echo "Hitting introspect endpoint for ${1} token"
	if [ $MODE == "pkce" ] && [ $CLIENT_TYPE == "public" ]; then
		echo ""
		echo "Using the INTROSPECT CLIENT_ID and CLIENT_SECRET for client: $INTROSPECT_CLIENT_ID "
		INTROSPECT=$($CURL --request POST --user "$INTROSPECT_CLIENT_ID:$INTROSPECT_CLIENT_SECRET" --data "token=${2}" "$AM_INTROSPECT" | jq .)
		echo ""
		echo $INTROSPECT | jq .
	else
		echo ""
		INTROSPECT=$($CURL --request POST --user "$CLIENT_ID:$CLIENT_SECRET" --data "token=${2}" "$AM_INTROSPECT" | jq .)
	fi
	echo $INTROSPECT | jq .
	echo ""
	echo "*********************"
}

hitUserInfo() {
	echo "Hitting userinfo endpoint"
	USERINFO=$($CURL --request POST --Cookie "$AM_COOKIENAME=$SSO_TOKEN" --header "Authorization: Bearer $ACCESS_TOKEN" -d '' "$AM_USERINFO" | jq .)
	echo $USERINFO | jq .
	echo ""
	echo "*********************"
}

refreshToken() {
	echo "Using the following refresh tokento generate new access token:"
	echo "$REFRESH_TOKEN"
	echo
	echo "Current access token is: $ACCESS_TOKEN"
	TOKENS=$($CURL --request POST --data "grant_type=refresh_token&refresh_token=$REFRESH_TOKEN&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=$SCOPES" "$AM_ACCESS_TOKEN" | jq .)
	ACCESS_TOKEN=$(echo $TOKENS | jq -r .access_token)
	REFRESH_TOKEN=$(echo $TOKENS | jq -r .refresh_token)
	ID_TOKEN=$(echo $TOKENS | jq -r .id_token)
	echo
	echo "New access token is $ACCESS_TOKEN"
	echo "*********************"
	echo "New id_token is: $ID_TOKEN"
}

endSession() {
	echo "Hitting endSession"
	$CURL --request GET --header "Authorization: Bearer $ACCESS_TOKEN" "$AM_ENDSESSION?id_token_hint=$ID_TOKEN&post_logout_redirect_uri=$POST_LOGOUT_REDIRECT_URI&client_id=$CLIENT_ID" | jq .
	echo "*********************"
}

revokeOauth2Tokens() {
	echo "Using this ${1} Token to revoke both the refresh and access token: ${2}"
	$CURL --request POST --user "$CLIENT_ID:$CLIENT_SECRET" --data "client_id=$CLIENT_ID&token=${2}" "$AM_REVOKE" | jq .
	echo "Tokens deleted"
	echo "*********************"
}

#Functions
jqCheck
clear
getCookieName
authN
validateSession
gen_PKCEMaterial
getAuthCode
getTokens
decodeJWT Access ${ACCESS_TOKEN}
decodeJWT Refresh  ${REFRESH_TOKEN}
decodeJWT id_token  ${ID_TOKEN}
hitTokenInfo
hitIntrospectAccessToken Access ${ACCESS_TOKEN}
hitIntrospectAccessToken Refresh ${REFRESH_TOKEN}
hitUserInfo ${ACCESS_TOKEN}
refreshToken
hitIntrospectAccessToken Access ${ACCESS_TOKEN}
endSession
revokeOauth2Tokens Refresh ${REFRESH_TOKEN}
validateSession