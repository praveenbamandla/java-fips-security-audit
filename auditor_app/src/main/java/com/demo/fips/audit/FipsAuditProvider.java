package com.demo.fips.audit;

import java.io.File;
import java.io.FileInputStream;
import java.lang.instrument.Instrumentation;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.Provider;
import java.security.Security;
import java.time.Instant;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * JCA Security Provider &mdash; FIPS Audit Bridge
 *
 * <p>Sits at JCA position 1 and intercepts every {@code getInstance()} call.
 * Uses a two-layer classification to decide what to audit:</p>
 *
 * <ol>
 *   <li><b>BCFIPS probe</b> &mdash; calls {@code bcfips.getService(type, algorithm)}
 *       to determine whether the algorithm is FIPS-approved.  If BCFIPS
 *       does not recognise the algorithm in approved-only mode, it is
 *       classified as {@code DISALLOWED} and logged.</li>
 *   <li><b>Policy file</b> ({@code fips-policy.properties}) &mdash; flags
 *       configurations that are technically FIPS-valid but operationally
 *       weak or deprecated (e.g.&nbsp;AES/ECB, SHA-1, 3DES).  These are
 *       classified as {@code WEAK} and logged.</li>
 * </ol>
 *
 * <p>All actual cryptographic operations are delegated to native JCA
 * providers (SUN, SunJCE, etc.).  BCFIPS is used <em>only</em> as a
 * FIPS-compliance oracle and is never registered in the JCA provider
 * chain &mdash; this avoids the StackOverflowError caused by its internal
 * circular SecureRandom bootstrap.</p>
 *
 * <p>Designed as a <b>Java agent</b> for zero-touch attachment to any
 * Java application.  The agent's {@code premain()} inserts this provider
 * at JCA position 1 before the application starts, leaving the JDK's
 * default {@code java.security} configuration completely untouched.</p>
 *
 * <pre>
 * Primary usage (Java agent — recommended):
 *   -javaagent:/path/to/fips-audit-provider.jar
 *   -Dorg.bouncycastle.fips.approved_only=true
 *   -Dfips.audit.log=/path/to/fips-audit.log
 *   -Dfips.audit.stack.depth=30
 *   -Dfips.audit.dedupe=true
 *
 * To enable the BCFIPS approved-mode probe (Layer 1), also add:
 *   -Xbootclasspath/a:/path/to/bc-fips-2.0.0.jar
 *   (without it, only policy-file rules in fips-policy.properties apply)
 *
 * Alternative usage (security properties — NOT recommended):
 *   -Djava.security.properties=security-audit.properties
 *     WARNING: use single = only; double == replaces the entire
 *     java.security file and breaks SSL/TLS.
 * </pre>
 */
public final class FipsAuditProvider extends Provider {

    private static final String NAME    = "FipsAudit";
    private static final String VERSION = "1.0";
    private static final String INFO    =
            "FIPS Audit Bridge: logs non-FIPS JCA usage and delegates to native providers";

    // -- Configuration -------------------------------------------------------
    //
    //  Settings are resolved in order:
    //    1. System property  (-Dfips.audit.log=...)
    //    2. Config file      (<java.home>/conf/fips-audit.properties)
    //    3. Built-in default
    //
    //  The config file is loaded once on first access.  When deployed via
    //  the JRE patch approach, the file lives inside the patched JRE and
    //  can be edited without recompilation.
    //

    private static final String CONFIG_FILE = "fips-audit.properties";
    private static volatile Properties configProps;

    /**
     * Returns the effective value for a configuration key.
     * Checks system properties first, then the config file, then the default.
     */
    static String config(String key, String defaultValue) {
        // 1. System property takes priority (allows -D override)
        String val = System.getProperty(key);
        if (val != null) return val.trim();

        // 2. Config file
        Properties props = loadConfig();
        val = props.getProperty(key);
        if (val != null) return val.trim();

        // 3. Built-in default
        return defaultValue;
    }

    private static Properties loadConfig() {
        Properties p = configProps;
        if (p != null) return p;

        p = new Properties();
        try {
            // Look in <java.home>/conf/fips-audit.properties
            String javaHome = System.getProperty("java.home");
            if (javaHome != null) {
                File f = new File(javaHome, "conf" + File.separator + CONFIG_FILE);
                if (f.isFile()) {
                    try (FileInputStream fis = new FileInputStream(f)) {
                        p.load(fis);
                    }
                    System.err.println("[FipsAudit] Config loaded: " + f.getAbsolutePath()
                            + " (" + p.size() + " entries)");
                }
            }
        } catch (Throwable t) {
            System.err.println("[FipsAudit] WARNING: cannot load config file: " + t);
        }
        configProps = p;  // benign race -- Properties is read-only after load
        return p;
    }

    /**
     * Re-entrancy guard: depth counter tracking nested entries into
     * getService / newInstance.  When depth &gt; 0 we are already inside
     * an audit-layer call and must bypass to avoid infinite recursion.
     */
    static final ThreadLocal<Integer> DEPTH = ThreadLocal.withInitial(() -> 0);

    /**
     * Tracks the full cipher transformation string detected during the
     * {@code getService()} lookup sequence (e.g.&nbsp;"AES/ECB/PKCS5Padding").
     *
     * <p>JCA calls {@code getService()} with the full transformation first,
     * then falls back to the base algorithm ("AES").  We capture the
     * transformation here so that {@code newInstance()} can extract the
     * mode and padding for a policy-file lookup.</p>
     */
    static final ThreadLocal<String> PENDING_CIPHER_TRANSFORM = new ThreadLocal<>();

    // ── Direct BCFIPS provider reference (NOT in JCA chain) ────────────

    private static volatile Provider bcfipsInstance;

    /** Configurable policy engine &mdash; loaded once on first use. */
    private static volatile FipsPolicy fipsPolicy;

    // ── BCFIPS management ──────────────────────────────────────────────

    /**
     * Register a pre-constructed BouncyCastleFipsProvider instance as the
     * FIPS-compliance oracle.  Optional &mdash; if not called, BCFIPS is
     * auto-initialised from the classpath on first use.
     */
    public static void setBcfipsProvider(Provider bcfips) {
        bcfipsInstance = bcfips;
        System.err.println("[FipsAudit] BCFIPS provider set: "
                + bcfips.getName() + " v" + bcfips.getVersion()
                + " (FIPS oracle - NOT in JCA chain)");
    }

    public static Provider getBcfipsProvider() {
        return bcfipsInstance;
    }

    /**
     * Lazily creates a BouncyCastleFipsProvider instance for use as a
     * FIPS-compliance oracle.  The instance is <em>not</em> registered in
     * the JCA provider chain &mdash; it is only used to probe whether an
     * algorithm is FIPS-approved.
     *
     * <p>This method is <b>lock-free</b> to avoid deadlocks with JCA's
     * internal locks.  If two threads race to initialise BCFIPS, one wins
     * the CAS and does the work; the other skips Layer&nbsp;1 for that
     * single call (and will pick up the result on the next call).</p>
     *
     * <p>If construction fails for any reason (class not on classpath,
     * BCFIPS internal error, etc.) the failure is logged once and
     * subsequent calls return {@code null} immediately, falling back
     * to policy-file-only mode.</p>
     */
    private static final int INIT_NOT_STARTED = 0;
    private static final int INIT_IN_PROGRESS = 1;
    private static final int INIT_DONE        = 2;
    private static final int INIT_FAILED      = 3;
    private static final AtomicInteger bcfipsInitState = new AtomicInteger(INIT_NOT_STARTED);

    /**
     * Default directory (relative to {@code java.home}) where the unmodified
     * {@code bc-fips-*.jar} can be placed for automatic discovery when the
     * audit provider is embedded in a JRE image via {@code jlink}.
     *
     * <p>This avoids the need for {@code -Xbootclasspath/a} or any
     * command-line / environment variable configuration &mdash; ideal for
     * JNI-embedded JVMs where the C++ launcher calls
     * {@code JNI_CreateJavaVM} directly.</p>
     */
    private static final String BCFIPS_LIB_DIR = "lib" + File.separator + "fips";

    private static Provider autoInitBcfips() {
        Provider p = bcfipsInstance;
        if (p != null) return p;

        // Non-blocking: if another thread is already initialising, skip
        // Layer 1 for this one call rather than blocking (which deadlocks
        // with JCA's internal locks).
        int state = bcfipsInitState.get();
        if (state == INIT_FAILED) return null;
        if (state == INIT_IN_PROGRESS) return null;
        if (!bcfipsInitState.compareAndSet(INIT_NOT_STARTED, INIT_IN_PROGRESS)) {
            return bcfipsInstance;   // another thread just finished or is in progress
        }

        try {
            // Ensure BCFIPS runs in approved-only mode so getService()
            // returns null for non-FIPS algorithms.  This property must
            // be set BEFORE the BouncyCastleFipsProvider constructor runs.
            // If already set (e.g. via -D flag or JAVA_TOOL_OPTIONS), we
            // leave the existing value untouched.
            if (System.getProperty("org.bouncycastle.fips.approved_only") == null) {
                System.setProperty("org.bouncycastle.fips.approved_only", "true");
                System.err.println("[FipsAudit] Set org.bouncycastle.fips.approved_only=true");
            }

            // Strategy 1: try the current classloader (works when bc-fips is
            //             on the bootclasspath via -Xbootclasspath/a or the
            //             application classpath)
            Class<?> cls = null;
            try {
                cls = Class.forName(
                        "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider");
            } catch (ClassNotFoundException ignored) {
                // Not on classpath — fall through to Strategy 2
            }

            // Strategy 2: scan <java.home>/lib/fips/ for bc-fips-*.jar and
            //             load via URLClassLoader.  This is the primary path
            //             when the audit provider is jlinked into a JRE and
            //             bc-fips.jar is dropped into lib/fips/.
            if (cls == null) {
                cls = loadBcfipsFromJreLib();
            }

            if (cls == null) {
                throw new ClassNotFoundException(
                        "BouncyCastleFipsProvider not found on classpath or in "
                        + BCFIPS_LIB_DIR);
            }

            p = (Provider) cls.getDeclaredConstructor().newInstance();
            bcfipsInstance = p;
            bcfipsInitState.set(INIT_DONE);
            System.err.println("[FipsAudit] BCFIPS auto-initialised: "
                    + p.getName() + " v" + p.getVersion()
                    + " (FIPS oracle - NOT in JCA chain)");
        } catch (Throwable t) {
            bcfipsInitState.set(INIT_FAILED);
            System.err.println("[FipsAudit] WARNING: cannot initialise BCFIPS - "
                    + "audit limited to policy-file rules only: " + t);
        }
        return p;
    }

    /**
     * Scans {@code <java.home>/lib/fips/} for JARs matching
     * {@code bc-fips*.jar} and loads {@code BouncyCastleFipsProvider}
     * via a dedicated {@link URLClassLoader}.
     *
     * <p>The bc-fips JAR is loaded <em>unmodified</em>, preserving its
     * FIPS self-integrity checksum.  The URLClassLoader is kept alive
     * (referenced by the loaded class) for the lifetime of the JVM.</p>
     *
     * @return the {@code BouncyCastleFipsProvider} class, or {@code null}
     */
    private static Class<?> loadBcfipsFromJreLib() {
        try {
            String javaHome = System.getProperty("java.home");
            if (javaHome == null) return null;

            File fipsDir = new File(javaHome, BCFIPS_LIB_DIR);
            if (!fipsDir.isDirectory()) {
                System.err.println("[FipsAudit] BCFIPS lib dir not found: "
                        + fipsDir.getAbsolutePath()
                        + " — Layer 1 (BCFIPS probe) disabled");
                return null;
            }

            // Collect all JARs in the fips directory
            File[] jars = fipsDir.listFiles(
                    (dir, name) -> name.toLowerCase().endsWith(".jar"));
            if (jars == null || jars.length == 0) {
                System.err.println("[FipsAudit] No JARs in "
                        + fipsDir.getAbsolutePath()
                        + " — Layer 1 (BCFIPS probe) disabled");
                return null;
            }

            URL[] urls = new URL[jars.length];
            for (int i = 0; i < jars.length; i++) {
                urls[i] = jars[i].toURI().toURL();
                System.err.println("[FipsAudit] Loading BCFIPS JAR: "
                        + jars[i].getName());
            }

            // Parent = platform class loader so bc-fips can see java.base,
            // java.security.Provider, etc. but not application classes.
            URLClassLoader cl = new URLClassLoader(
                    urls, ClassLoader.getPlatformClassLoader());

            return Class.forName(
                    "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider",
                    true, cl);
        } catch (Throwable t) {
            System.err.println("[FipsAudit] WARNING: failed to load BCFIPS "
                    + "from " + BCFIPS_LIB_DIR + ": " + t);
            return null;
        }
    }

    // ── Policy engine ──────────────────────────────────────────────────
    //
    //  Lock-free lazy init: FipsPolicy is immutable after construction,
    //  so a benign data race (two threads creating separate instances,
    //  one discarded by GC) is safe and avoids deadlocking with JCA's
    //  internal locks.
    //

    static FipsPolicy policy() {
        FipsPolicy p = fipsPolicy;
        if (p == null) {
            p = new FipsPolicy();
            fipsPolicy = p;   // benign race — FipsPolicy is read-only
        }
        return p;
    }

    // ── Audit logger ───────────────────────────────────────────────────
    //
    //  Lock-free lazy init: the Logger and its handlers are append-only
    //  after setup.  A benign race may create duplicate handlers once,
    //  but that is harmless and avoids deadlocking with JCA's internal
    //  locks (which are held while JCA calls our getService).
    //

    private static volatile Logger auditLog;
    private static volatile int stackDepth;

    static Logger auditLogger() {
        Logger log = auditLog;
        if (log == null) {
            stackDepth = safeParseInt(
                    config("fips.audit.stack.depth", "20"), 20);
            log = buildLogger();
            auditLog = log;   // benign race -- Logger is thread-safe
        }
        return log;
    }

    private static int safeParseInt(String value, int fallback) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            System.err.println("[FipsAudit] WARNING: invalid integer '" + value
                    + "', using default " + fallback);
            return fallback;
        }
    }

    private static Logger buildLogger() {
        String logFile = config("fips.audit.log", "fips-audit.log");
        Logger log = Logger.getLogger("com.demo.fips.audit");
        log.setUseParentHandlers(false);
        log.setLevel(Level.ALL);

        ConsoleHandler ch = new ConsoleHandler();
        ch.setFormatter(new PlainFormatter());
        ch.setLevel(Level.ALL);
        log.addHandler(ch);

        try {
            FileHandler fh = new FileHandler(logFile, true);
            fh.setFormatter(new PlainFormatter());
            fh.setLevel(Level.ALL);
            log.addHandler(fh);
            System.err.println("[FipsAudit] Audit log -> " + logFile);
        } catch (Exception e) {
            System.err.println("[FipsAudit] WARNING: cannot open log file '"
                    + logFile + "': " + e.getMessage() + " - stderr only");
        }
        return log;
    }

    // ── Java Agent entry points ─────────────────────────────────────
    //
    //  When loaded as a Java agent (-javaagent:fips-audit-provider.jar),
    //  premain() inserts this provider at JCA position 1 before the
    //  application's main() method runs.  This avoids manipulating
    //  java.security / security-audit.properties entirely, so all JDK
    //  default security settings (SSL/TLS, keystores, etc.) remain intact.
    //

    /**
     * Java agent entry point &mdash; called before {@code main()}.
     * Inserts this provider at JCA position 1.
     */
    public static void premain(String agentArgs, Instrumentation inst) {
        installProvider();
    }

    /**
     * Dynamic-attach agent entry point &mdash; called when attaching to a
     * running JVM via the Attach API.
     */
    public static void agentmain(String agentArgs, Instrumentation inst) {
        installProvider();
    }

    private static void installProvider() {
        try {
            FipsAuditProvider provider = new FipsAuditProvider();
            Security.insertProviderAt(provider, 1);
            System.err.println("[FipsAudit] Provider installed at JCA position 1 (via agent)");
        } catch (Throwable t) {
            System.err.println("[FipsAudit] ERROR: failed to install provider: " + t);
        }
    }

    // ── Constructor ────────────────────────────────────────────────────

    public FipsAuditProvider() {
        super(NAME, VERSION, INFO);
        System.err.println("[FipsAudit] Provider instantiated.");
    }

    // ── getService ─────────────────────────────────────────────────────
    //
    //  Called by JCA for every getInstance() lookup.
    //
    //  SecureRandom is ALWAYS routed to native (SUN) to avoid BCFIPS's
    //  internal circular bootstrap (StackOverflowError).
    //
    //  A depth counter prevents re-entrant calls during BCFIPS's
    //  getService (e.g. internal KeyGenerator / Cipher lookup).
    //

    @Override
    public Provider.Service getService(String type, String algorithm) {

        // ── SecureRandom: never intercept ──
        if ("SecureRandom".equals(type)) {
            return null;
        }

        // ── Cipher transformation tracking ──
        // JCA tries the full transformation first ("AES/ECB/PKCS5Padding")
        // before the base algorithm ("AES").  Capture it for later policy
        // lookup, then return null so JCA falls through to base algorithm.
        if ("Cipher".equals(type) && algorithm.contains("/")) {
            PENDING_CIPHER_TRANSFORM.set(algorithm);
            return null;
        }

        // ── Re-entrancy guard ──
        int depth = DEPTH.get();
        if (depth > 0) {
            return null;
        }

        DEPTH.set(depth + 1);
        try {
            performAudit(type, algorithm);
        } catch (Throwable t) {
            // Catch Throwable (not just Exception) because BCFIPS can
            // throw Error subclasses (FipsOperationError, AssertionError).
            // Audit must NEVER affect the application.
            System.err.println("[FipsAudit] WARNING: audit failed for "
                    + type + "/" + algorithm + ": " + t);
        } finally {
            DEPTH.set(depth);
        }

        // Always return null — let JCA resolve the real provider naturally.
        // This ensures the audit layer never interferes with provider
        // selection, SSL/TLS context creation, or any other JCA operation.
        return null;
    }

    // ── Audit logic (fire-and-forget, never blocks JCA) ────────────────

    private void performAudit(String type, String algorithm) {
        // Retrieve cipher transformation captured in earlier getService() call
        String fullTransform = PENDING_CIPHER_TRANSFORM.get();
        PENDING_CIPHER_TRANSFORM.remove();

        Provider bcfips = bcfipsInstance;
        if (bcfips == null) {
            bcfips = autoInitBcfips();
        }

        // ── Layer 1: BCFIPS oracle (auto-initialised or via setBcfipsProvider) ──
        boolean fipsApproved = true;   // assume approved if no BCFIPS
        if (bcfips != null) {
            try {
                fipsApproved = bcfips.getService(type, algorithm) != null;
            } catch (Throwable t) {
                // Catch Throwable — BCFIPS can throw Error subclasses
                System.err.println("[FipsAudit] WARNING: BCFIPS probe failed for "
                        + type + "/" + algorithm + ": " + t);
                return;   // cannot determine status — skip audit
            }
        }

        if (!fipsApproved) {
            String displayAlgo = fullTransform != null ? fullTransform : algorithm;
            logAudit("DISALLOWED", type, displayAlgo,
                    "Algorithm not available in BCFIPS approved-only mode");
            return;
        }

        // ── Layer 2: Policy file ──
        String mode    = null;
        String padding = null;
        if (fullTransform != null) {
            String[] parts = fullTransform.split("/");
            if (parts.length >= 2) mode    = parts[1];
            if (parts.length >= 3) padding = parts[2];
        }

        FipsPolicy.PolicyResult result =
                policy().lookup(type, algorithm, mode, padding);

        if (result.classification() != FipsPolicy.Classification.APPROVED) {
            String label  = result.classification().name();
            String algo   = fullTransform != null ? fullTransform : algorithm;
            String reason = result.reason() != null
                    ? result.reason()
                    : label + " per fips-policy.properties";
            logAudit(label, type, algo, reason);
        }
    }

    // ── Deduplication ───────────────────────────────────────────────
    //
    // Keyed on classification + type + algorithm + first app-level
    // caller frame.  Controlled by -Dfips.audit.dedupe (default true).
    //

    private static final Set<String> SEEN_AUDITS =
            ConcurrentHashMap.newKeySet();

    private static final boolean DEDUPE_ENABLED =
            !"false".equalsIgnoreCase(
                    config("fips.audit.dedupe", "true"));

    // ── Audit logging ──────────────────────────────────────────────────

    static void logAudit(String classification, String type,
                         String algorithm, String reason) {
        Logger log = auditLogger();
        StackTraceElement[] frames = Thread.currentThread().getStackTrace();

        // Find the first application-level caller frame for dedup key
        String callerOrigin = "";
        for (StackTraceElement f : frames) {
            String cls = f.getClassName();
            if (cls.startsWith("java.") || cls.startsWith("javax.")
                    || cls.startsWith("jdk.") || cls.startsWith("sun.")
                    || cls.startsWith("com.demo.fips.audit.")) continue;
            callerOrigin = f.toString();
            break;
        }

        if (DEDUPE_ENABLED) {
            String dedupeKey = classification + "|" + type + "|" + algorithm
                    + "|" + callerOrigin;
            if (!SEEN_AUDITS.add(dedupeKey)) {
                // Already logged for this exact origin — skip
                return;
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("FIPS AUDIT - ").append(classification).append('\n');
       // sb.append("  Timestamp : ").append(Instant.now()).append('\n');
        sb.append("  JCA type  : ").append(type).append('\n');
        sb.append("  Algorithm : ").append(algorithm).append('\n');
        sb.append("  Reason    : ").append(reason).append('\n');
        sb.append("  Caller stack (application frames):\n");
        int printed = 0;
        int limit = stackDepth > 0 ? stackDepth : 20;
        for (StackTraceElement f : frames) {
            String cls = f.getClassName();
            if (cls.startsWith("java.") || cls.startsWith("javax.")
                    || cls.startsWith("jdk.") || cls.startsWith("sun.")
                    || cls.startsWith("com.demo.fips.audit.")) continue;
            sb.append("    at ").append(f).append('\n');
            if (++printed >= limit) {
                sb.append("    ... (truncated)\n");
                break;
            }
        }
        log.warning(sb.toString());
    }

    // ── Log formatter ──────────────────────────────────────────────────

    private static final class PlainFormatter extends Formatter {
        @Override
        public String format(LogRecord r) { return r.getMessage() + "\n"; }
    }
}
