package org.brekka.phoenix;

import org.brekka.commons.lang.BaseException;


/**
 * @author Andrew Taylor
 */
public class PhoenixException extends BaseException {

    /**
     * Serial UID
     */
    private static final long serialVersionUID = -4138976811848253266L;

    /**
     * @param errorCode
     * @param message
     * @param messageArgs
     */
    public PhoenixException(PhoenixErrorCode errorCode, String message, Object... messageArgs) {
        super(errorCode, message, messageArgs);
    }

    /**
     * @param errorCode
     * @param cause
     * @param message
     * @param messageArgs
     */
    public PhoenixException(PhoenixErrorCode errorCode, Throwable cause, String message, Object... messageArgs) {
        super(errorCode, cause, message, messageArgs);
    }

}
