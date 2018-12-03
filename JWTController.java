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

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    // Datapine SSO shared secret
    private String secret;

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

        String jwt = jws.getCompactSerialization();

        // Issue a redirect. The redirect url is received as request parameter, and JWT is appended
        return new ModelAndView(String.format("redirect:%s?token=%s", ssoCallback, jwt));

    }

}
