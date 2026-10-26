# BcJavaCheck: a small command line over the OpenPGP API of Bouncy Castle Java 1.86 (see BcJavaCheck.java), to compare
# Bouncy Castle C# with the Java implementation directly, including byte-for-byte re-encoding of keys and signatures.
# Build context: this folder.
FROM eclipse-temurin:21-jdk
WORKDIR /opt/bcjava
ADD --checksum=sha256:2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f \
    https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.86/bcprov-jdk18on-1.86.jar lib/
ADD --checksum=sha256:8a52ea45b2063f6d41b8ca94409f255a1f4604922f7451c18a7cfd3a3c5b85ab \
    https://repo1.maven.org/maven2/org/bouncycastle/bcpg-jdk18on/1.86/bcpg-jdk18on-1.86.jar lib/
ADD --checksum=sha256:1c268e15f785aafb1e4670d8d6e5f856f69475e96c162dadcd1ff9b350e9139f \
    https://repo1.maven.org/maven2/org/bouncycastle/bcutil-jdk18on/1.86/bcutil-jdk18on-1.86.jar lib/
COPY BcJavaCheck.java .
RUN javac -cp 'lib/*' -d classes BcJavaCheck.java
ENTRYPOINT ["java", "-cp", "/opt/bcjava/classes:/opt/bcjava/lib/*", "BcJavaCheck"]
