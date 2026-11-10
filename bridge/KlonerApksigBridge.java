/*
 * KLONER apksig bridge.
 *
 * A thin, read-only wrapper around Google's apksig (the library behind apksigner).
 * It verifies one APK per request and prints exactly one JSON object per request.
 *
 * Modes:
 *   --version                                   print bridge/apksig identity
 *   --verify PATH --min-sdk N --max-sdk M       one-shot verification
 *   --serve                                     JSON Lines over stdin/stdout
 *
 * Serve-mode request (one per line):
 *   {"id":"<opaque>","path":"<file>","min_sdk":24,"max_sdk":2147483647}
 *   {"id":"<opaque>","op":"version"}
 *
 * The bridge never writes files and opens the APK read-only (apksig uses RandomAccessFile "r").
 */

import com.android.apksig.ApkVerifier;
import com.android.apksig.SigningCertificateLineage;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.cert.CertificateEncodingException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class KlonerApksigBridge {
    static final String BRIDGE_VERSION = "2";
    static final int MAX_REQUEST_CHARS = 1 << 16;

    private KlonerApksigBridge() {}

    public static void main(String[] args) throws Exception {
        PssAliases.installIfMissing();
        PrintWriter out = new PrintWriter(new OutputStreamWriter(System.out, StandardCharsets.UTF_8), false);
        if (args.length == 1 && "--version".equals(args[0])) {
            out.println(versionJson(null));
            out.flush();
            return;
        }
        if (args.length == 1 && "--serve".equals(args[0])) {
            serve(out);
            return;
        }
        if (args.length == 6 && "--verify".equals(args[0]) && "--min-sdk".equals(args[2])
                && "--max-sdk".equals(args[4])) {
            int min = Integer.parseInt(args[3]);
            int max = Integer.parseInt(args[5]);
            out.println(verifyJson(null, args[1], min, max));
            out.flush();
            return;
        }
        System.err.println("usage: KlonerApksigBridge --version | --serve | --verify PATH --min-sdk N --max-sdk M");
        System.exit(2);
    }

    static void serve(PrintWriter out) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line;
        while ((line = in.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }
            String response;
            try {
                if (line.length() > MAX_REQUEST_CHARS) {
                    throw new IllegalArgumentException("request too large");
                }
                Map<String, Object> req = MiniJson.parseFlatObject(line);
                String id = req.containsKey("id") ? String.valueOf(req.get("id")) : null;
                String op = req.containsKey("op") ? String.valueOf(req.get("op")) : "verify";
                if ("quit".equals(op)) {
                    break;
                } else if ("version".equals(op)) {
                    response = versionJson(id);
                } else if ("verify".equals(op)) {
                    String path = (String) req.get("path");
                    int min = ((Long) req.get("min_sdk")).intValue();
                    int max = ((Long) req.get("max_sdk")).intValue();
                    response = verifyJson(id, path, min, max);
                } else {
                    throw new IllegalArgumentException("unknown op");
                }
            } catch (Throwable t) {
                JsonWriter w = new JsonWriter();
                w.beginObject();
                w.field("bridge_version", BRIDGE_VERSION);
                w.field("fatal", "BridgeRequestError: " + t.getClass().getSimpleName() + ": " + t.getMessage());
                w.endObject();
                response = w.toString();
            }
            out.println(response);
            out.flush();
        }
        out.flush();
    }

    static String versionJson(String id) {
        JsonWriter w = new JsonWriter();
        w.beginObject();
        if (id != null) {
            w.field("id", id);
        }
        w.field("bridge_version", BRIDGE_VERSION);
        w.field("apksig_jar_sha256", apksigJarSha256());
        w.field("java_version", System.getProperty("java.version"));
        w.endObject();
        return w.toString();
    }

    static String apksigJarSha256() {
        try {
            URI uri = ApkVerifier.class.getProtectionDomain().getCodeSource().getLocation().toURI();
            File f = new File(uri);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (InputStream is = new FileInputStream(f)) {
                byte[] buf = new byte[1 << 16];
                int n;
                while ((n = is.read(buf)) > 0) {
                    md.update(buf, 0, n);
                }
            }
            return hex(md.digest());
        } catch (Exception e) {
            return null;
        }
    }

    static String verifyJson(String id, String path, int minSdk, int maxSdk) {
        JsonWriter w = new JsonWriter();
        w.beginObject();
        if (id != null) {
            w.field("id", id);
        }
        w.field("bridge_version", BRIDGE_VERSION);
        w.field("apksig_jar_sha256", apksigJarSha256());
        w.key("input");
        w.beginObject();
        w.field("path", path);
        w.field("min_sdk", minSdk);
        w.field("max_sdk", maxSdk);
        w.endObject();
        try {
            File file = new File(path);
            ApkVerifier.Builder b = new ApkVerifier.Builder(file);
            b.setMinCheckedPlatformVersion(minSdk);
            b.setMaxCheckedPlatformVersion(maxSdk);
            ApkVerifier.Result r = b.build().verify();
            w.field("verified", r.isVerified());
            w.key("schemes");
            w.beginObject();
            w.field("v1", r.isVerifiedUsingV1Scheme());
            w.field("v2", r.isVerifiedUsingV2Scheme());
            w.field("v3", r.isVerifiedUsingV3Scheme());
            w.field("v31", r.isVerifiedUsingV31Scheme());
            w.field("v4", r.isVerifiedUsingV4Scheme());
            w.endObject();

            w.key("signers");
            w.beginArray();
            int i = 0;
            for (ApkVerifier.Result.V1SchemeSignerInfo s : r.getV1SchemeSigners()) {
                writeV1Signer(w, s, i++, false);
            }
            i = 0;
            for (ApkVerifier.Result.V1SchemeSignerInfo s : r.getV1SchemeIgnoredSigners()) {
                writeV1Signer(w, s, i++, true);
            }
            for (ApkVerifier.Result.V2SchemeSignerInfo s : r.getV2SchemeSigners()) {
                w.beginObject();
                w.field("scheme", "v2");
                w.field("index", s.getIndex());
                writeCert(w, s.getCertificate());
                w.key("chain");
                writeCertDigests(w, s.getCertificates());
                w.nullField("min_sdk");
                w.nullField("max_sdk");
                w.nullField("lineage");
                writeIssues(w, "errors", s.getErrors());
                writeIssues(w, "warnings", s.getWarnings());
                w.endObject();
            }
            writeV3Signers(w, "v3", r.getV3SchemeSigners());
            writeV3Signers(w, "v31", r.getV31SchemeSigners());
            w.endArray();

            w.key("lineage");
            writeLineage(w, r.getSigningCertificateLineage());

            w.key("signer_certificates");
            writeCertDigests(w, r.getSignerCertificates());

            w.key("source_stamp");
            ApkVerifier.Result.SourceStampInfo st = r.getSourceStampInfo();
            w.beginObject();
            if (st == null) {
                w.field("present", false);
                w.nullField("status");
                w.nullField("cert_sha256");
                w.nullField("cert_der_b64");
            } else {
                w.field("present", true);
                w.field("status", String.valueOf(st.getSourceStampVerificationStatus()));
                X509Certificate sc = st.getCertificate();
                if (sc == null) {
                    w.nullField("cert_sha256");
                    w.nullField("cert_der_b64");
                } else {
                    w.field("cert_sha256", certSha256(sc));
                    w.field("cert_der_b64", certB64(sc));
                }
                w.field("timestamp_epoch_s", st.getTimestampEpochSeconds());
                writeIssues(w, "errors", st.getErrors());
                writeIssues(w, "warnings", st.getWarnings());
            }
            w.field("verified", r.isSourceStampVerified());
            w.endObject();

            writeIssues(w, "errors", r.getErrors());
            writeIssues(w, "warnings", r.getWarnings());
            writeIssues(w, "all_errors", r.getAllErrors());
            w.nullField("fatal");
        } catch (Throwable t) {
            w.field("verified", false);
            w.field("fatal", t.getClass().getName() + ": " + String.valueOf(t.getMessage()));
        }
        w.endObject();
        return w.toString();
    }

    static void writeV1Signer(JsonWriter w, ApkVerifier.Result.V1SchemeSignerInfo s, int index, boolean ignored) {
        w.beginObject();
        w.field("scheme", "v1");
        w.field("index", index);
        w.field("ignored", ignored);
        w.field("name", s.getName());
        w.field("signature_block_file", s.getSignatureBlockFileName());
        w.field("signature_file", s.getSignatureFileName());
        writeCert(w, s.getCertificate());
        w.key("chain");
        writeCertDigests(w, s.getCertificateChain());
        w.nullField("min_sdk");
        w.nullField("max_sdk");
        w.nullField("lineage");
        writeIssues(w, "errors", s.getErrors());
        writeIssues(w, "warnings", s.getWarnings());
        w.endObject();
    }

    static void writeV3Signers(JsonWriter w, String scheme, List<ApkVerifier.Result.V3SchemeSignerInfo> signers) {
        for (ApkVerifier.Result.V3SchemeSignerInfo s : signers) {
            w.beginObject();
            w.field("scheme", scheme);
            w.field("index", s.getIndex());
            writeCert(w, s.getCertificate());
            w.key("chain");
            writeCertDigests(w, s.getCertificates());
            w.field("min_sdk", s.getMinSdkVersion());
            w.field("max_sdk", s.getMaxSdkVersion());
            w.field("rotation_targets_dev_release", s.getRotationTargetsDevRelease());
            w.key("lineage");
            writeLineage(w, s.getSigningCertificateLineage());
            writeIssues(w, "errors", s.getErrors());
            writeIssues(w, "warnings", s.getWarnings());
            w.endObject();
        }
    }

    static void writeLineage(JsonWriter w, SigningCertificateLineage lineage) {
        if (lineage == null) {
            w.nullValue();
            return;
        }
        w.beginArray();
        for (X509Certificate c : lineage.getCertificatesInLineage()) {
            w.beginObject();
            w.field("cert_sha256", certSha256(c));
            w.field("cert_der_b64", certB64(c));
            SigningCertificateLineage.SignerCapabilities caps = lineage.getSignerCapabilities(c);
            w.key("capabilities");
            w.beginObject();
            w.field("installed_data", caps.hasInstalledData());
            w.field("shared_uid", caps.hasSharedUid());
            w.field("permission", caps.hasPermission());
            w.field("rollback", caps.hasRollback());
            w.field("auth", caps.hasAuth());
            w.endObject();
            w.endObject();
        }
        w.endArray();
    }

    static void writeCert(JsonWriter w, X509Certificate c) {
        if (c == null) {
            w.nullField("cert_sha256");
            w.nullField("cert_der_b64");
            return;
        }
        w.field("cert_sha256", certSha256(c));
        w.field("cert_der_b64", certB64(c));
    }

    static void writeCertDigests(JsonWriter w, List<X509Certificate> certs) {
        w.beginArray();
        if (certs != null) {
            for (X509Certificate c : certs) {
                w.value(certSha256(c));
            }
        }
        w.endArray();
    }

    static void writeIssues(JsonWriter w, String name, List<? extends ApkVerifier.IssueWithParams> issues) {
        w.key(name);
        w.beginArray();
        if (issues != null) {
            for (ApkVerifier.IssueWithParams iwp : issues) {
                w.beginObject();
                w.field("issue", iwp.getIssue().name());
                w.key("params");
                w.beginArray();
                Object[] params = iwp.getParams();
                if (params != null) {
                    for (Object p : params) {
                        w.value(p == null ? null : String.valueOf(p));
                    }
                }
                w.endArray();
                w.field("message", iwp.toString());
                w.endObject();
            }
        }
        w.endArray();
    }

    static String certSha256(X509Certificate c) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return hex(md.digest(c.getEncoded()));
        } catch (CertificateEncodingException | java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static String certB64(X509Certificate c) {
        try {
            return Base64.getEncoder().encodeToString(c.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }

    /** Minimal JSON writer producing ASCII-only output. */
    static final class JsonWriter {
        private final StringBuilder sb = new StringBuilder(4096);
        /** One entry per open container: true once the container holds at least one item. */
        private final ArrayList<Boolean> hasItems = new ArrayList<>();
        /** True right after a key was written: the next value belongs to it and takes no comma. */
        private boolean afterKey = false;

        private void beforeValue() {
            if (afterKey) {
                afterKey = false;
                return;
            }
            if (!hasItems.isEmpty()) {
                int top = hasItems.size() - 1;
                if (hasItems.get(top)) {
                    sb.append(',');
                } else {
                    hasItems.set(top, true);
                }
            }
        }

        void beginObject() { beforeValue(); sb.append('{'); hasItems.add(false); }
        void endObject() { sb.append('}'); hasItems.remove(hasItems.size() - 1); }
        void beginArray() { beforeValue(); sb.append('['); hasItems.add(false); }
        void endArray() { sb.append(']'); hasItems.remove(hasItems.size() - 1); }

        void key(String k) {
            beforeValue();
            str(k);
            sb.append(':');
            afterKey = true;
        }

        void field(String k, String v) { key(k); value(v); }
        void field(String k, long v) { key(k); beforeValue(); sb.append(v); }
        void field(String k, boolean v) { key(k); beforeValue(); sb.append(v ? "true" : "false"); }
        void nullField(String k) { key(k); nullValue(); }

        void nullValue() { beforeValue(); sb.append("null"); }

        void value(String v) {
            beforeValue();
            if (v == null) {
                sb.append("null");
            } else {
                str(v);
            }
        }

        private void str(String s) {
            sb.append('"');
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '"': sb.append("\\\""); break;
                    case '\\': sb.append("\\\\"); break;
                    case '\n': sb.append("\\n"); break;
                    case '\r': sb.append("\\r"); break;
                    case '\t': sb.append("\\t"); break;
                    default:
                        if (c < 0x20 || c > 0x7e) {
                            sb.append(String.format("\\u%04x", (int) c));
                        } else {
                            sb.append(c);
                        }
                }
            }
            sb.append('"');
        }

        @Override
        public String toString() { return sb.toString(); }
    }

    /** Parser for flat JSON objects whose values are strings, integers, booleans or null. */
    static final class MiniJson {
        private final String s;
        private int i;

        private MiniJson(String s) { this.s = s; }

        static Map<String, Object> parseFlatObject(String s) {
            MiniJson p = new MiniJson(s);
            Map<String, Object> m = p.object();
            p.ws();
            if (p.i != p.s.length()) {
                throw new IllegalArgumentException("trailing data");
            }
            return m;
        }

        private void ws() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
                i++;
            }
        }

        private char peek() {
            if (i >= s.length()) {
                throw new IllegalArgumentException("unexpected end");
            }
            return s.charAt(i);
        }

        private void expect(char c) {
            ws();
            if (peek() != c) {
                throw new IllegalArgumentException("expected " + c);
            }
            i++;
        }

        private Map<String, Object> object() {
            Map<String, Object> m = new LinkedHashMap<>();
            expect('{');
            ws();
            if (peek() == '}') {
                i++;
                return m;
            }
            while (true) {
                ws();
                String k = string();
                expect(':');
                ws();
                m.put(k, scalar());
                ws();
                char c = peek();
                i++;
                if (c == '}') {
                    return m;
                }
                if (c != ',') {
                    throw new IllegalArgumentException("expected , or }");
                }
            }
        }

        private Object scalar() {
            char c = peek();
            if (c == '"') {
                return string();
            }
            if (s.startsWith("true", i)) { i += 4; return Boolean.TRUE; }
            if (s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
            if (s.startsWith("null", i)) { i += 4; return null; }
            int start = i;
            if (c == '-') {
                i++;
            }
            while (i < s.length() && Character.isDigit(s.charAt(i))) {
                i++;
            }
            if (start == i || (s.charAt(start) == '-' && i == start + 1)) {
                throw new IllegalArgumentException("bad scalar");
            }
            return Long.parseLong(s.substring(start, i));
        }

        private String string() {
            if (peek() != '"') {
                throw new IllegalArgumentException("expected string");
            }
            i++;
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = peek();
                i++;
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    char e = peek();
                    i++;
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            if (i + 4 > s.length()) {
                                throw new IllegalArgumentException("bad escape");
                            }
                            sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                            i += 4;
                            break;
                        default:
                            throw new IllegalArgumentException("bad escape");
                    }
                } else {
                    sb.append(c);
                }
            }
        }
    }

    /**
     * apksig asks the JCA for "SHA256withRSA/PSS" and "SHA512withRSA/PSS" (the names Android's Conscrypt
     * provides). Desktop JDKs implement the same algorithm as "RSASSA-PSS", configured by the PSSParameterSpec
     * apksig sets. When the names are missing, this registers verify-only adapters so that APKs signed with
     * RSA-PSS verify on the desktop exactly as on a device. Signing is refused.
     */
    static final class PssAliases extends Provider {
        private static final long serialVersionUID = 1L;

        private PssAliases() {
            super("KlonerPssAliases", "1.0", "SHAxxxwithRSA/PSS names mapped to the JDK's RSASSA-PSS (verify only)");
            put("Signature.SHA256withRSA/PSS", PssVerifier.class.getName());
            put("Signature.SHA512withRSA/PSS", PssVerifier.class.getName());
        }

        static void installIfMissing() {
            try {
                Signature.getInstance("SHA256withRSA/PSS");
                return; // a provider already offers the names
            } catch (NoSuchAlgorithmException e) {
                // fall through
            }
            try {
                Signature.getInstance("RSASSA-PSS");
            } catch (NoSuchAlgorithmException e) {
                return; // nothing to map to; apksig reports the failure itself
            }
            Security.addProvider(new PssAliases());
        }
    }

    /** Verify-only SignatureSpi delegating to the JDK's RSASSA-PSS. */
    public static final class PssVerifier extends SignatureSpi {
        private final Signature delegate;

        public PssVerifier() throws NoSuchAlgorithmException {
            delegate = Signature.getInstance("RSASSA-PSS");
        }

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
            delegate.initVerify(publicKey);
        }

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
            throw new InvalidKeyException("the KLONER bridge only verifies");
        }

        @Override
        protected void engineUpdate(byte b) throws SignatureException {
            delegate.update(b);
        }

        @Override
        protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
            delegate.update(b, off, len);
        }

        @Override
        protected byte[] engineSign() throws SignatureException {
            throw new SignatureException("the KLONER bridge only verifies");
        }

        @Override
        protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
            return delegate.verify(sigBytes);
        }

        @Override
        protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
            delegate.setParameter(params);
        }

        @Override
        @Deprecated
        protected void engineSetParameter(String param, Object value) {
            throw new InvalidParameterException("unsupported");
        }

        @Override
        @Deprecated
        protected Object engineGetParameter(String param) {
            throw new InvalidParameterException("unsupported");
        }
    }
}
