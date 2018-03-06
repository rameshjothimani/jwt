package com.webtoken.sign;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.Certificate;
import java.security.cert.*;
import java.security.interfaces.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import javax.crypto.*;

import com.ibm.crypto.pkcs11impl.provider.*;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;

public class Signature {

    public static void main(String args[]) {

        String keystorePass="password";
        String keyPass="password";

        String alias="securitytest";


        Key key=null;
        java.security.cert.Certificate cert=null;

        try {

            InputStream keystoreStream = new FileInputStream("C://keystore.jck");
            KeyStore keystore = KeyStore.getInstance("JCEKS");
            keystore.load(keystoreStream, keystorePass.toCharArray());

        if (!keystore.containsAlias(alias)) {
            throw new RuntimeException("Alias for key not found");
        }
        key = keystore.getKey(alias, keyPass.toCharArray());

        cert = keystore.getCertificate(alias);

        } catch (FileNotFoundException filenotfoundexcep){
            filenotfoundexcep.printStackTrace();
        }catch(KeyStoreException keystoreException){
            keystoreException.printStackTrace();
        }catch(CertificateException certificateException){
            certificateException.printStackTrace();
        }catch(IOException ioException){
            ioException.printStackTrace();
        }catch(NoSuchAlgorithmException nosuchAlgorithmException){
            nosuchAlgorithmException.printStackTrace();
        }catch(UnrecoverableKeyException unrecoverableKeyException){
            unrecoverableKeyException.printStackTrace();
        }


        /*Private Key from the JCK file*/
        RSAPrivateKey privateKey=(RSAPrivateKey)key;

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

        String s = jwsObject.serialize();

        System.out.println("Signed text :::" + s);


        // To parse the JWS and verify it, e.g. on client-side
        try {
            jwsObject = JWSObject.parse(s);
        }catch(ParseException parseEx){
            parseEx.printStackTrace();
        }

        System.out.println("Input text ::"+ jwsObject.getPayload().toString());


        /*Get the public key from JCK file*/
        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey)cert.getPublicKey());


        try {
            /*Verify the content signature*/
            if(jwsObject.verify(verifier))
            {
                System.out.println("Verified ::"+jwsObject.getPayload().toString());
            }else{
                System.out.println("Verification failed !!!");
            }

        }catch (JOSEException joseException){
            joseException.printStackTrace();
        }



    }
}
