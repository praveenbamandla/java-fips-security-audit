/**
 * FIPS Audit Provider module.
 *
 * <p>When embedded in a JRE image via {@code jlink}, this module is
 * automatically available to the platform class loader, allowing the
 * provider to be registered in {@code conf/security/java.security}
 * with zero command-line arguments:</p>
 *
 * <pre>
 *   security.provider.1=com.demo.fips.audit.FipsAuditProvider
 * </pre>
 *
 * <p>This is the recommended deployment model for applications that
 * bootstrap the JVM from native code (JNI {@code JNI_CreateJavaVM})
 * where {@code -javaagent} and {@code JAVA_TOOL_OPTIONS} cannot be
 * used reliably.</p>
 */
module com.demo.fips.audit {

    // JCA provider framework
    requires java.base;

    // java.util.logging for audit output
    requires java.logging;

    // java.lang.instrument for the optional agent entry points
    requires java.instrument;

    // Export the provider package so java.security can instantiate it
    exports com.demo.fips.audit;

    // Register as a JCA security provider via ServiceLoader
    provides java.security.Provider
        with com.demo.fips.audit.FipsAuditProvider;
}
