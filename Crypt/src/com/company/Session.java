package com.company;

import javax.crypto.SecretKey;

public class Session {

    SecretKey secretKey;
    String algorithm;
    String friend;

    public Session(SecretKey secretKey, String algorithm, String friend){

        this.secretKey = secretKey;
        this.algorithm = algorithm;
        this.friend = friend;

    }

}
