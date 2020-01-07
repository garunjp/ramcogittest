package org.wso2.apimgt.keymgt.ramco.keystore;

import com.auth0.jwk.*;
import com.auth0.jwt.exceptions.TokenExpiredException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;

public class RamcoKeyStore{
    private static final Log log = LogFactory.getLog(RamcoKeyStore.class);
    private static RSAPublicKey publicKey=null;
    private static  String JWK_URL=null;
    private static String PUBLIC_KEY_ID=null;
    private static String USER_NAME_IDENTIFIER = null;
    private static String CONSUMER_KEY_IDENTIFIER = null;

    public static RSAPublicKey getPublicKey() throws JwkException, MalformedURLException, APIManagementException {
        if(JWK_URL==null || PUBLIC_KEY_ID==null){
            String msg= "Ramco JWK URL || PUBLIC KEY ID is not configured properly";
            log.error(msg);
            throw new APIManagementException(msg);
        }
        JwkProvider provider = new UrlJwkProvider(new URL(JWK_URL));
        Jwk jwk = provider.get(PUBLIC_KEY_ID);
        publicKey =  (RSAPublicKey)jwk.getPublicKey();
        return publicKey;
    }

    public static Claims decodeJWT(String jwtToken) throws MalformedURLException, JwkException, APIManagementException {
        try {
            //If public key is not initialised, initialize it from ramco jwk url
            if(publicKey==null){
                publicKey = getPublicKey();
            }

            Claims claims = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(jwtToken).getBody();
            if(log.isDebugEnabled()){
                log.debug("Ramco Claim Properties");
                log.debug("ID: " + claims.getId());
                log.debug("Subject: " + claims.getSubject());
                log.debug("Issuer: " + claims.getIssuer());
                log.debug("Expiration: " + claims.getExpiration());
            }
            return claims;
        }catch (InvalidPublicKeyException pe){
            //if public key is invalid, reinitialize and call the same method
            String msg= "JWT Token Expired";
            log.error(msg, pe);
            publicKey = getPublicKey();
            decodeJWT(jwtToken);
            throw new APIManagementException(msg);
        }catch (TokenExpiredException te){
            String msg= "JWT Token Expired";
            log.error(msg, te);
            throw new APIManagementException(msg);
        }
        catch (Exception e){
            String msg= "Error Validating Ramco JWT using public key";
            log.error(msg, e);
            throw new APIManagementException(msg);
        }
    }

    public static String getJwkUrl() {
        return JWK_URL;
    }

    public static void setJwkUrl(String jwkUrl) {
        JWK_URL = jwkUrl;
    }

    public static String getPublicKeyId() {
        return PUBLIC_KEY_ID;
    }

    public static void setPublicKeyId(String publicKeyId) {
        PUBLIC_KEY_ID = publicKeyId;
    }

    public static String getUserNameIdentifier() {
        return USER_NAME_IDENTIFIER;
    }

    public static void setUserNameIdentifier(String userNameIdentifier) {
        USER_NAME_IDENTIFIER = userNameIdentifier;
    }

    public static String getConsumerKeyIdentifier() {
        return CONSUMER_KEY_IDENTIFIER;
    }

    public static void setConsumerKeyIdentifier(String consumerKeyIdentifier) {
        CONSUMER_KEY_IDENTIFIER = consumerKeyIdentifier;
    }
}
