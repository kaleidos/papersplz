package papersplz

import spock.lang.*

class CryptoSpec extends Specification {

    def crypto = new Crypto('mysupersecret')

    void 'Getting a salt'() {
        setup: 'getting a salt'
            def salt = crypto.getSalt()
            println salt

        expect: 'a correctly formatted salt'
            salt.size() == 16
    }

}
