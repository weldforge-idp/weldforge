Feature: The client address behind a proxy
  Rate limiting, account lockout, the audit trail and refresh-token
  provenance all key on one value: the client's IP address. The server sits
  behind a TLS-terminating proxy, so that address arrives in a forwarded
  header, and a header is something the caller can write.

  The boundary that decides which forwarded entries to believe is
  server.tomcat.remoteip.internal-proxies. It used to trust every hop, which
  means it believed the leftmost entry in the chain — the one the caller
  chooses. A caller could therefore pick its own rate-limit bucket, its own
  audit IP, and the IP recorded against its session (B-AUTH-1).

  Background:
    Given the server trusts only its own proxy hops

  Scenario: A caller cannot choose its own rate-limit bucket
    When a request arrives forwarded as "203.0.113.77, 198.51.100.9"
    Then the client address is "198.51.100.9"
    And the forged entry "203.0.113.77" is not the client address

  Scenario: A longer forged prefix changes nothing
    When a request arrives forwarded as "203.0.113.77, 203.0.113.78, 198.51.100.9"
    Then the client address is "198.51.100.9"

  Scenario: Internal hops are skipped, forged entries are not believed
    When a request arrives forwarded as "203.0.113.77, 198.51.100.9, 10.42.0.22"
    Then the client address is "198.51.100.9"

  Scenario: The ordinary case still reports the real caller
    When a request arrives forwarded as "198.51.100.9"
    Then the client address is "198.51.100.9"

  Scenario: With nothing forwarded, the connection's own peer is the client
    When a request arrives with nothing forwarded
    Then the client address is the connecting peer

  Scenario: The proxy can still tell the server the request was HTTPS
    When a request arrives forwarded as HTTPS
    Then the server treats the request as HTTPS

  Scenario: The boundary is not a wildcard
    Then the configured trust boundary is not a wildcard
    And a public address is not treated as one of our proxies
