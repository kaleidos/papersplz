package papersplz

import groovy.util.logging.Slf4j

import groovy.json.JsonBuilder
import groovy.json.JsonSlurper

import org.joda.time.DateTime
import org.joda.time.format.DateTimeFormatter
import org.joda.time.format.ISODateTimeFormat

@Slf4j
class JWT {
    private static final String BEARER = "Bearer "

    Integer expirationTime
    CryptoProvider crypto

    JWT(String secret, Integer expirationTime, CryptoProvider crypto = null) {
        this.crypto = crypto ?: new Crypto(secret)
        this.expirationTime = expirationTime
    }

    String generateToken(String userName, String salt = null, Map<String,String> extraData=[:]){
        def data = [username:userName]

        if (extraData) {
            data["extradata"] = extraData
        }

        if (salt != null) {
            data["salt"] = salt
        }

        DateTimeFormatter formatter = ISODateTimeFormat.dateTime()
        data["issued_at"] = formatter.print(new DateTime())

        if (expirationTime != null) {
            data["expires_at"] = formatter.print(new DateTime().plusMinutes(expirationTime))
        }

        String header = new JsonBuilder([alg:"HS256", typ: "JWT"])
        String payload = new JsonBuilder(data).toString()
        String signature = crypto.hash("${header.bytes.encodeBase64()}.${payload.bytes.encodeBase64()}")

        return "${header.bytes.encodeBase64()}.${payload.bytes.encodeBase64()}.${signature}"
    }

    Map extractToken(String token) {
        if (!token) {
            log.debug "Token must be present"
            throw new StatelessValidationException("Malformed token")
        }

        if (token.startsWith(BEARER)){
            token = token.substring(BEARER.size())
        }

        def (header64, payload64, signature) = token.tokenize(".")

        if (header64 == null || payload64 == null || signature == null) {
            log.debug "Token should have two points to split"
            throw new StatelessValidationException("Malformed token")
        }

        // Extract the payload
        def slurper = new JsonSlurper()
        def payload = new String(payload64.decodeBase64())
        Map tokenData = (Map)slurper.parseText(payload)

        tokenData += [
            header64: header64,
            payload64: payload64,
            signature: signature
        ]

        return tokenData
    }

    void validateToken(Map tokenData, salt = null) {
        // Validate signature
        String expectedSignature = crypto.hash("${tokenData.header64}.${tokenData.payload64}")

        if (tokenData.signature != expectedSignature) {
            throw new StatelessValidationException("Invalid token")
        }

        // Check salt
        if (salt && tokenData.salt != salt) {
            throw new StatelessValidationException("Invalid token")
        }
    }
}
