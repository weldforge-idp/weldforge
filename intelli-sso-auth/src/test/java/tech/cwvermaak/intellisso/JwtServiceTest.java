@Test
void generateToken_positive_valid() {
    String token = jwtService.generateToken("test@example.com");
    assertNotNull(token);
    assertTrue(jwtService.isTokenValid(token));
}

@Test
void extractEmail_negative_invalidToken() {
    assertThrows(Exception.class, () -> jwtService.extractEmail("invalid.token"));
}