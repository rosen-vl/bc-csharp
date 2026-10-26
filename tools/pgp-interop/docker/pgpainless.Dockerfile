# pgpainless-cli 2.0.4 (PGPainless on Bouncy Castle Java 1.84): the Stateless OpenPGP CLI over BC Java, which supports
# the version 6 formats of RFC 9580 but not the algorithms of RFC 9980.
FROM eclipse-temurin:21-jre
ADD --checksum=sha256:b565409efed35916afea2a1b33187e69d35170001b03b1c15a39e16c4c515354 \
    https://repo1.maven.org/maven2/org/pgpainless/pgpainless-cli/2.0.4/pgpainless-cli-2.0.4-all.jar \
    /opt/pgpainless-cli.jar
ENTRYPOINT ["java", "-jar", "/opt/pgpainless-cli.jar"]
