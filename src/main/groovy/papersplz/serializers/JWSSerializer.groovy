package papersplz.serializers

import groovy.util.logging.Slf4j

import groovy.json.JsonBuilder
import groovy.json.JsonSlurper

import org.joda.time.DateTime
import org.joda.time.format.DateTimeFormatter
import org.joda.time.format.ISODateTimeFormat

import papersplz.InvalidTokenException
import papersplz.Serializer

@Slf4j
class JWSSerializer implements Serializer {
    private static final String BEARER = 'Bearer '

    Integer expirationTime
    Crypto crypto

    JWSSerializer(String secret, Integer expirationTime = null) {
        if (!secret) {
            throw new RuntimeException('"secret" parameter cannot be null')
        }
        this.crypto = new Crypto(secret)
        this.expirationTime = expirationTime
    }

    @Override
    String serialize(Map data) {
        DateTimeFormatter formatter = ISODateTimeFormat.dateTime()
        data["issued_at"] = formatter.print(new DateTime())

        if (expirationTime != null) {
            data["expires_at"] = formatter.print(new DateTime().plusMinutes(expirationTime))
        }

        String header = new JsonBuilder([alg: 'HS256', typ: 'JWT'])
        String payload = new JsonBuilder(data).toString()
        String signature = crypto.hash("${header.bytes.encodeBase64()}.${payload.bytes.encodeBase64()}")

        return "${header.bytes.encodeBase64()}.${payload.bytes.encodeBase64()}.${signature}"
    }

    @Override
    Map parse(String token) throws InvalidTokenException {
        if (!token) {
            log.debug 'Token must be present'
            throw new InvalidTokenException('Malformed Token')
        }

        if (token.startsWith(BEARER)){
            token = token.substring(BEARER.size())
        }

        def (header64, payload64, signature) = token.tokenize('.')

        if (header64 == null || payload64 == null || signature == null) {
            log.debug 'Token should have two points to split'
            throw new InvalidTokenException('Malformed Token')
        }

        // Extract the payload
        def slurper = new JsonSlurper()
        def payload = new String(payload64.decodeBase64())
        Map tokenData = (Map)slurper.parseText(payload)

        tokenData['_token'] = [
            header64: header64,
            payload64: payload64,
            signature: signature
        ]

        return tokenData
    }

    @Override
    Boolean validate(Map tokenData, String salt) {
        // Validate signature
        String expectedSignature = crypto.hash("${tokenData['_token'].header64}.${tokenData['_token'].payload64}")

        if (tokenData['_token'].signature != expectedSignature) {
            return false
        }

        // Check salt
        if (salt && tokenData.salt != salt) {
            return false
        }
        return true
    }

    Boolean validate(Map tokenData) {
        return validate(tokenData, null)
    }
}
