package papersplz

interface Serializer {
    String serialize(Map data)
    Map parse(String token) throws InvalidTokenException
    Boolean validate(Map tokenData, String salt)
}
