package papersplz

import spock.lang.*

class JWTSpec extends Specification {

    JWT jwt = new JWT('mysupersecret', 10)

    void 'Generate a valid token'() {
        given: 'Some data for the token'
            def username = 'jane_doe'
            def salt = 'Some salted data'
            def extraData = [age: 'undefined', sex: 'Female']

        when: 'trying to generate a token'
            def token = jwt.generateToken(username, salt, extraData)

        and: 'validating it'
            def tokenData = jwt.extractToken(token)

        then: 'the token should be valid'
            token
            tokenData.username == username
            tokenData.salt == salt
            tokenData.extradata == extraData
            tokenData.containsKey('header64')
            tokenData.containsKey('payload64')
            tokenData.containsKey('signature')
    }

    void 'Check valid token with salt'() {
        given: 'Some data for the token'
            def username = 'jane_doe'
            def salt = 'Some salted data'
            def extraData = [age: 'undefined', sex: 'Female']

        and: 'a token generated from that data'
            def token = jwt.generateToken(username, salt, extraData)

        and: 'the tokenData map obtained from it'
            def tokenData = jwt.extractToken(token)

        when: 'validating it'
            def result = jwt.validateToken(tokenData, salt)

        then: 'everything should be ok'
            result
    }

    void 'Check invalid token due salt'() {
        given: 'Some data for the token'
            def username = 'jane_doe'
            def salt = 'Some salted data'
            def otherSalt = 'Different salted data'
            def extraData = [age: 'undefined', sex: 'Female']

        and: 'a token generated from that data'
            def token = jwt.generateToken(username, salt, extraData)

        and: 'the tokenData map obtained from it'
            def tokenData = jwt.extractToken(token)

        when: 'validating it'
            def result = jwt.validateToken(tokenData, otherSalt)

        then: 'the validation should return false'
            result == false
    }

    void 'Check invalid token due bad signature'() {
        given: 'Some data for the token'
            def username = 'jane_doe'
            def salt = 'Some salted data'
            def extraData = [age: 'undefined', sex: 'Female']

        and: 'a token generated from that data'
            def token = jwt.generateToken(username, salt, extraData)

        and: 'the tokenData map obtained from it with an invalid header'
            def tokenData = jwt.extractToken(token)
            tokenData.header64 = 'bad header'

        when: 'validating it'
            def result = jwt.validateToken(tokenData, salt)

        then: 'the validation should return false'
            result == false
    }

}
