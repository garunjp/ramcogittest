package org.wso2.apimgt.keymgt.ramco.exception;

public class TokenAPIException extends Exception {

    public TokenAPIException(String msg) {
        super(msg);
    }

    public TokenAPIException(String msg, Throwable e) {
     //Added for gittest
        super(msg, e);
    }
}
