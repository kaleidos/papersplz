package papersplz.serializers

import spock.lang.*

import papersplz.InvalidTokenException

class JWSSerializerSpec extends Specification {

    JWSSerializer jws = new JWSSerializer('mysupersecret', 10)

    void 'Generate a valid token'() {
        given: 'Some data for the token'
            def data = [
                username: 'jane_doe',
                salt: 'Some salted data',
                age: 'undefined',
                sex: 'Female'
            ]

        when: 'trying to generate a token'
            def token = jws.serialize(data)

        and: 'validating it'
            def tokenData = jws.parse(token)

        then: 'the token should be valid'
            token
            tokenData.username == data.username
            tokenData.salt == data.salt
            tokenData.age == data.age
            tokenData.sex == data.sex
            tokenData.containsKey('_token')
            tokenData['_token'].containsKey('header64')
            tokenData['_token'].containsKey('payload64')
            tokenData['_token'].containsKey('signature')
    }

    void 'Check valid token with salt'() {
        given: 'Some data for the token'
            def data = [
                username: 'jane_doe',
                salt: 'Some salted data',
                age: 'undefined',
                sex: 'Female'
            ]

        and: 'a token generated from that data'
            def token = jws.serialize(data)

        and: 'the tokenData map obtained from it'
            def tokenData = jws.parse(token)

        when: 'validating it'
            def result = jws.validate(tokenData, data.salt)

        then: 'everything should be ok'
            result
    }

    void 'Check invalid token due salt'() {
        given: 'Some data for the token'
            def data = [
                username: 'jane_doe',
                salt: 'Some salted data',
                age: 'undefined',
                sex: 'Female'
            ]

        and: 'a different salt that the one included in the token'
            def otherSalt = 'Different salted data'

        and: 'a token generated from that data'
            def token = jws.serialize(data)

        and: 'the tokenData map obtained from it'
            def tokenData = jws.parse(token)

        when: 'validating it'
            def result = jws.validate(tokenData, otherSalt)

        then: 'the validation should return false'
            result == false
    }

    void 'Check invalid token due bad signature'() {
        given: 'Some data for the token'
            def data = [
                username: 'jane_doe',
                salt: 'Some salted data',
                age: 'undefined',
                sex: 'Female'
            ]

        and: 'a token generated from that data'
            def token = jws.serialize(data)

        and: 'the tokenData map obtained from it with an invalid header'
            def tokenData = jws.parse(token)
            tokenData['_token'].header64 = 'bad header'

        when: 'validating it'
            def result = jws.validate(tokenData, data.salt)

        then: 'the validation should return false'
            result == false
    }

    void 'Check malformed token'() {
        given: 'A malformed token'
            def token = 'malformed token'

        when: 'trying to parse it'
            jws.parse(token)

        then: 'an exception should be raised'
            thrown InvalidTokenException
    }

    void 'Check null token'() {
        given: 'A null token'
            def token = null

        when: 'trying to parse it'
            jws.parse(token)

        then: 'an exception should be raised'
            thrown InvalidTokenException
    }

    void 'Trying to instantiate JWSSerializer without secret'() {
        when: 'Instantiating JWSSerializer'
            new JWSSerializer('')
        then: 'an exception must be thrown'
            thrown RuntimeException
    }
}
