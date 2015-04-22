package papersplz

import groovy.transform.CompileStatic

@CompileStatic
class InvalidTokenException extends RuntimeException {
    InvalidTokenException(String message) {
        super(message)
    }

    InvalidTokenException(String message, Throwable cause) {
        super(message, cause)
    }
}
