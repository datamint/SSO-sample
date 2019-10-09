package com.datapine.controllers;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class JWTController {

    // Datapine SSO shared secret
    private String secret;

    // Datapine SSO ras public key
    private String RSAPublic;

    @RequestMapping(value = "/remote/login/url", method = RequestMethod.GET)
    public ModelAndView singleSignOn(@RequestParam(value = "ssoCallback") String ssoCallback) throws JoseException {

        // Set some initial properties of the JWT
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("Organization");
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
	    // This property can be empty, but must be present in token
	    claims.setAudience("");

        // Set the user
        claims.setSubject("user@customer.com");

        // Set additional customization properties
        claims.setClaim("dashboards", "[\"Marketing\", \"Management\"]");
        claims.setClaim("filters", "[{\"name\":\"Country\",\"values\":[\"Spain\",\"Germany\"],\"visible\":true}]");

        // Sign the token via shared secret
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(new HmacKey(secret.getBytes()));
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);

        String innerJwt = jws.getCompactSerialization();

        //Until here was same example as before, now we are going to create the new encrpyted token and use the token above as payload

        PublicKey myPublicKey = readPublicKey(RSAPublic);
        //we need to build the headers with the algorithms identifiers, in this case we use RSA_OAEP_256 and AES_128_GCM
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_GCM);
        //We need to add the key
        jwe.setKey(myPublicKey); //public key used for encryption
        jwe.setKeyIdHeaderValue(rsaKey.getKeyId()); //this optional, if you want give an id to the key
        //And we need to add the payload
        jwe.setContentTypeHeaderValue("JWT"); //this is important, so we know inside in payload there is another jwt token
        jwe.setPayload(innerJwt); //we attach previous token as payload

        String encryptedJWT = jwe.getCompactSerialization();


        // Issue a redirect. The redirect url is received as request parameter, and JWT is appended
        return new ModelAndView(String.format("redirect:%s?token=%s", ssoCallback, encryptedJWT));

    }

    //Public key it is Base64 encode
    //This is a key example and method how to read it
    //-----BEGIN PUBLIC KEY-----
    //MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqyk2vPCIFBF9n29MIhpSWNS4md/PK2X8
    //S+IAWvMQmEpDVWlDEgM+gRHfke2HS9WOnkSUXy7Wug2cbK1Ah3BUsO0m3Cr0F0Fk4LUN25O/Fiof
    //9r7gFaMSHd7VZ2327/mTU13ouTcxu0+pm4F3+rzphQC9NA7ZsEUhZ+DyY4V1LPUjUujBETUXMPYs
    //YClglogTx62hmVIo31cMWiO68YVutDySv3mhAhQjPShGEm+byva2bKMsAl6wqvSx3cFzscwhKq5s
    //BaUV5Y6W04/E71voj6flhBADA5q6bE3EcflB7f1D59LQ5628eOX2GLX7ibo7foz4d1vDtB/Gu6Y7
    //iqfFGQIDAQAB
    //-----END PUBLIC KEY-----
    private PublicKey readPublicKey(String rsaPublic) throws InvalidKeySpecException, NoSuchAlgorithmException {
        String publicPemFormat = rsaPublic.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicPemFormat)));
    }

}
