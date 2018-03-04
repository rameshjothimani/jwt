package com.webtoken.sign;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.*;
import java.text.ParseException;
import javax.crypto.*;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;

public class Signature {

public static void main(String args[]) {


    // RSA signatures require a public and private RSA key pair,
// the public key must be made known to the JWS recipient to
// allow the signatures to be verified
    KeyPairGenerator keyGenerator = null;
    try {
        keyGenerator = KeyPairGenerator. getInstance("RSA");
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
    keyGenerator.initialize(1024);

    KeyPair kp = keyGenerator.genKeyPair();
    RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
    System.out.println("Public Key::"+ publicKey.toString() );

    RSAPrivateKey privateKey = (RSAPrivateKey) kp.getPrivate();

    System.out.println("Private Key::"+ publicKey.toString() );

    // Create RSA-signer with the private key
    JWSSigner signer = new RSASSASigner(privateKey);

    // Prepare JWS object with simple string as payload
    JWSObject jwsObject = new JWSObject(
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("123").build(),
            new Payload("Ramesh"));

// Compute the RSA signature

    try{
        jwsObject.sign(signer);
    }catch(JOSEException exception){
        exception.printStackTrace();
    }


    // To serialize to compact form, produces something like
// eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
// mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
// maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
// -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
    String s = jwsObject.serialize();

    System.out.print("Signed text :::" + s);


// To parse the JWS and verify it, e.g. on client-side
    try {
        jwsObject = JWSObject.parse(s);
    }catch(ParseException parseEx){
        parseEx.printStackTrace();
    }

    System.out.println("Source ::"+ jwsObject.getPayload().toString());


    JWSVerifier verifier = new RSASSAVerifier(publicKey);


    try {
        jwsObject.verify(verifier);
    }catch (JOSEException joseException){
        joseException.printStackTrace();
    }

    System.out.println("Verified:::"+jwsObject.getPayload().toString());

}
}