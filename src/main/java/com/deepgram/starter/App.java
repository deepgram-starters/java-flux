/**
 * Java Flux Starter - Backend Server
 *
 * WebSocket bridge to Deepgram's Flux API (Listen v2) using the official
 * Deepgram Java SDK (`client.listen().v2().v2WebSocket()`) instead of a raw
 * Jetty WebSocket client.
 *
 * The browser-facing contract is unchanged: the browser streams binary PCM
 * audio and a `{"type":"CloseStream"}` control message to /api/flux, and the
 * backend forwards Deepgram's native Flux JSON (TurnInfo, Connected, ...) back
 * to the browser verbatim.
 *
 * Key Features:
 * - WebSocket bridge endpoint: /api/flux -> Deepgram Flux (SDK Listen v2)
 * - JWT session auth via access_token.<jwt> subprotocol
 * - Session endpoint: GET /api/session
 * - Metadata endpoint: GET /api/metadata
 */

package com.deepgram.starter;

// ============================================================================
// SECTION 1: IMPORTS
// ============================================================================

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.toml.TomlMapper;
import io.github.cdimascio.dotenv.Dotenv;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.websocket.WsConfig;
import io.javalin.websocket.WsContext;

import com.deepgram.DeepgramClient;
import com.deepgram.core.Environment;
import com.deepgram.resources.listen.v2.types.ListenV2CloseStream;
import com.deepgram.resources.listen.v2.websocket.V2ConnectOptions;
import com.deepgram.resources.listen.v2.websocket.V2WebSocketClient;
import com.deepgram.types.ListenV2EagerEotThreshold;
import com.deepgram.types.ListenV2Encoding;
import com.deepgram.types.ListenV2EotThreshold;
import com.deepgram.types.ListenV2EotTimeoutMs;
import com.deepgram.types.ListenV2Keyterm;
import com.deepgram.types.ListenV2Model;
import com.deepgram.types.ListenV2SampleRate;
import okio.ByteString;

import java.io.File;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

// ============================================================================
// SECTION 2: ENV LOADING
// ============================================================================

/**
 * Main application class for the Java Flux Starter.
 * Uses java-dotenv to load environment variables from .env file.
 */
public class App {

    /** Dotenv instance for loading .env variables */
    private static final Dotenv dotenv = Dotenv.configure()
            .ignoreIfMissing()
            .load();

    /** Shared Jackson ObjectMapper for JSON serialization */
    private static final ObjectMapper objectMapper = new ObjectMapper();

    // ========================================================================
    // SECTION 3: CONFIGURATION
    // ========================================================================

    /** Server port, configurable via PORT env var (default 8081) */
    private static final int PORT = Integer.parseInt(
            getEnv("PORT", "8081"));

    /** Server host, configurable via HOST env var (default 0.0.0.0) */
    private static final String HOST = getEnv("HOST", "0.0.0.0");

    /**
     * Reserved WebSocket close codes that cannot be set by applications.
     * If Deepgram sends one of these, we fall back to 1000 (normal closure).
     */
    private static final Set<Integer> RESERVED_CLOSE_CODES = Set.of(1004, 1005, 1006, 1015);

    // ========================================================================
    // SECTION 4: SESSION AUTH - JWT tokens for production security
    // ========================================================================

    /**
     * Session secret for signing JWTs.
     * Auto-generated if SESSION_SECRET env var is not set.
     */
    private static final String SESSION_SECRET = initSessionSecret();

    /** JWT expiry time: 1 hour (in seconds) */
    private static final long JWT_EXPIRY_SECONDS = 3600;

    /** HMAC-SHA256 algorithm instance for JWT signing/verification */
    private static final Algorithm jwtAlgorithm = Algorithm.HMAC256(SESSION_SECRET);

    /** JWT verifier instance, reused for all token validations */
    private static final JWTVerifier jwtVerifier = JWT.require(jwtAlgorithm).build();

    /**
     * Initializes the session secret from env or generates a random one.
     * @return The session secret string
     */
    private static String initSessionSecret() {
        String secret = getEnv("SESSION_SECRET", null);
        if (secret != null && !secret.isEmpty()) {
            return secret;
        }
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    /**
     * Creates a signed JWT for session authentication.
     * @return Signed JWT string
     */
    private static String createSessionToken() {
        Instant now = Instant.now();
        return JWT.create()
                .withIssuedAt(now)
                .withExpiresAt(now.plusSeconds(JWT_EXPIRY_SECONDS))
                .sign(jwtAlgorithm);
    }

    /**
     * Validates JWT from WebSocket subprotocol: access_token.<jwt>
     * Returns the full protocol string if valid, null if invalid.
     *
     * @param protocols The Sec-WebSocket-Protocol header value
     * @return The matching protocol string, or null
     */
    private static String validateWsToken(String protocols) {
        if (protocols == null || protocols.isEmpty()) return null;
        String[] list = protocols.split(",");
        for (String proto : list) {
            String trimmed = proto.trim();
            if (trimmed.startsWith("access_token.")) {
                String token = trimmed.substring("access_token.".length());
                try {
                    jwtVerifier.verify(token);
                    return trimmed;
                } catch (JWTVerificationException e) {
                    return null;
                }
            }
        }
        return null;
    }

    // ========================================================================
    // SECTION 5: API KEY LOADING
    // ========================================================================

    /** The Deepgram API key loaded at startup */
    private static String apiKey;

    /** One SDK client, reused across connections; the browser never sees the API key. */
    private static DeepgramClient deepgram;

    /**
     * Loads the Deepgram API key from environment variables.
     * Exits with a helpful error message if not found.
     *
     * @return The Deepgram API key
     */
    private static String loadApiKey() {
        String key = getEnv("DEEPGRAM_API_KEY", null);
        if (key == null || key.isEmpty() || key.equals("%api_key%")) {
            System.err.println();
            System.err.println("  ERROR: Deepgram API key not found!");
            System.err.println();
            System.err.println("Please set your API key using one of these methods:");
            System.err.println();
            System.err.println("1. Create a .env file (recommended):");
            System.err.println("   DEEPGRAM_API_KEY=your_api_key_here");
            System.err.println();
            System.err.println("2. Environment variable:");
            System.err.println("   export DEEPGRAM_API_KEY=your_api_key_here");
            System.err.println();
            System.err.println("Get your API key at: https://console.deepgram.com");
            System.err.println();
            System.exit(1);
        }
        return key;
    }

    // ========================================================================
    // SECTION 6: SETUP - Track connections
    // ========================================================================

    /** Track all active client WebSocket contexts for graceful shutdown */
    private static final Set<WsContext> activeConnections = ConcurrentHashMap.newKeySet();

    // ========================================================================
    // SECTION 7: HELPER FUNCTIONS
    // ========================================================================

    /**
     * Gets an environment variable with fallback to dotenv, then to a default.
     *
     * @param key          The environment variable name
     * @param defaultValue The default value if not found
     * @return The resolved value
     */
    private static String getEnv(String key, String defaultValue) {
        // System env takes priority (e.g., Docker, Fly.io)
        String value = System.getenv(key);
        if (value != null && !value.isEmpty()) {
            return value;
        }
        // Fall back to dotenv (.env file)
        try {
            value = dotenv.get(key);
            if (value != null && !value.isEmpty()) {
                return value;
            }
        } catch (Exception ignored) {
            // dotenv may not be available
        }
        return defaultValue;
    }

    /**
     * Returns a safe close code that can be sent over WebSocket.
     * Reserved codes (1004, 1005, 1006, 1015) are mapped to 1000 (normal closure).
     *
     * @param code The close code to check
     * @return A safe close code
     */
    private static int getSafeCloseCode(int code) {
        if (code >= 1000 && code <= 4999 && !RESERVED_CLOSE_CODES.contains(code)) {
            return code;
        }
        return 1000;
    }

    /**
     * Builds the Deepgram Flux connect options from the query parameters
     * forwarded by the client (the same parameters the previous raw-proxy
     * implementation appended to the Deepgram URL).
     *
     * @param ctx The client WebSocket context
     * @return The V2ConnectOptions for the Deepgram Flux connection
     */
    private static V2ConnectOptions buildConnectOptions(WsContext ctx) {
        String model = ctx.queryParam("model");
        if (model == null || model.isEmpty()) model = "flux-general-en";

        String encoding = ctx.queryParam("encoding");
        if (encoding == null || encoding.isEmpty()) encoding = "linear16";

        String sampleRate = ctx.queryParam("sample_rate");
        if (sampleRate == null || sampleRate.isEmpty()) sampleRate = "16000";

        V2ConnectOptions._FinalStage opts = V2ConnectOptions.builder()
                .model(ListenV2Model.valueOf(model))
                .encoding(ListenV2Encoding.valueOf(encoding))
                .sampleRate(ListenV2SampleRate.of(Integer.parseInt(sampleRate)));

        // Forward optional turn-detection parameters
        String eotThreshold = ctx.queryParam("eot_threshold");
        if (eotThreshold != null && !eotThreshold.isEmpty()) {
            opts = opts.eotThreshold(ListenV2EotThreshold.of(Double.parseDouble(eotThreshold)));
        }

        String eagerEotThreshold = ctx.queryParam("eager_eot_threshold");
        if (eagerEotThreshold != null && !eagerEotThreshold.isEmpty()) {
            opts = opts.eagerEotThreshold(ListenV2EagerEotThreshold.of(Double.parseDouble(eagerEotThreshold)));
        }

        String eotTimeoutMs = ctx.queryParam("eot_timeout_ms");
        if (eotTimeoutMs != null && !eotTimeoutMs.isEmpty()) {
            opts = opts.eotTimeoutMs(ListenV2EotTimeoutMs.of(Integer.parseInt(eotTimeoutMs)));
        }

        // Handle keyterm: can appear multiple times, forward all of them
        List<String> keyterms = ctx.queryParams("keyterm");
        List<String> filteredKeyterms = new ArrayList<>();
        if (keyterms != null) {
            for (String term : keyterms) {
                if (term != null && !term.isEmpty()) {
                    filteredKeyterms.add(term);
                }
            }
        }
        if (!filteredKeyterms.isEmpty()) {
            opts = opts.keyterm(ListenV2Keyterm.of(filteredKeyterms));
        }

        return opts.build();
    }

    // ========================================================================
    // SECTION 8: SESSION ROUTES
    // ========================================================================

    /**
     * GET /api/session - Issues a signed JWT for session authentication.
     *
     * @param ctx Javalin request context
     */
    private static void handleSession(Context ctx) {
        String token = createSessionToken();
        ctx.json(Map.of("token", token));
    }

    // ========================================================================
    // SECTION 9: API ROUTES & WEBSOCKET BRIDGE
    // ========================================================================

    /**
     * GET /api/metadata
     *
     * Returns metadata about this starter application from deepgram.toml.
     * Required for standardization compliance.
     *
     * @param ctx Javalin request context
     */
    private static void handleMetadata(Context ctx) {
        try {
            TomlMapper tomlMapper = new TomlMapper();
            JsonNode tomlData = tomlMapper.readTree(new File("deepgram.toml"));

            JsonNode meta = tomlData.get("meta");
            if (meta == null) {
                ctx.status(500).json(Map.of(
                        "error", "INTERNAL_SERVER_ERROR",
                        "message", "Missing [meta] section in deepgram.toml"
                ));
                return;
            }

            Map<String, Object> metaMap = objectMapper.treeToValue(meta, Map.class);
            ctx.json(metaMap);
        } catch (Exception e) {
            System.err.println("Error reading metadata: " + e.getMessage());
            ctx.status(500).json(Map.of(
                    "error", "INTERNAL_SERVER_ERROR",
                    "message", "Failed to read metadata from deepgram.toml"
            ));
        }
    }

    /**
     * Per-connection bridge to a Deepgram Flux WebSocket. Buffers audio that
     * arrives from the browser before the Deepgram socket has finished opening.
     */
    static final class FluxBridge {
        private final V2WebSocketClient dg;
        private boolean ready = false;
        private boolean closeRequested = false;
        private final List<ByteString> pendingAudio = new ArrayList<>();

        FluxBridge(V2WebSocketClient dg) {
            this.dg = dg;
        }

        synchronized void sendAudio(ByteString audio) {
            if (!ready) {
                pendingAudio.add(audio);
                return;
            }
            dg.sendMedia(audio);
        }

        synchronized void closeStream() {
            if (!ready) {
                closeRequested = true;
                return;
            }
            sendCloseStream();
        }

        synchronized void markReady() {
            ready = true;
            for (ByteString audio : pendingAudio) {
                dg.sendMedia(audio);
            }
            pendingAudio.clear();
            if (closeRequested) {
                sendCloseStream();
                closeRequested = false;
            }
        }

        private void sendCloseStream() {
            try {
                dg.sendCloseStream(ListenV2CloseStream.builder().build());
            } catch (Exception e) {
                System.err.println("Error sending CloseStream to Deepgram: " + e.getMessage());
            }
        }

        void disconnect() {
            try {
                dg.disconnect();
            } catch (Exception ignored) {
                // already closed
            }
        }
    }

    /**
     * Configures the /api/flux WebSocket endpoint.
     * Validates JWT from subprotocol on upgrade, then bridges the browser to
     * Deepgram's Flux API via the SDK's Listen v2 WebSocket client.
     *
     * @param ws Javalin WebSocket config
     */
    private static void handleFluxWebSocket(WsConfig ws) {

        ws.onConnect(ctx -> {
            // Validate JWT from access_token.<jwt> subprotocol
            String protocols = ctx.header("Sec-WebSocket-Protocol");
            String validProto = validateWsToken(protocols);
            if (validProto == null) {
                System.out.println("WebSocket auth failed: invalid or missing token");
                ctx.closeSession(4401, "Unauthorized");
                return;
            }

            System.out.println("Client connected to /api/flux (authenticated)");
            activeConnections.add(ctx);

            try {
                V2ConnectOptions options = buildConnectOptions(ctx);

                V2WebSocketClient dg = deepgram.listen().v2().v2WebSocket();
                FluxBridge bridge = new FluxBridge(dg);
                ctx.attribute("bridge", bridge);

                // Deepgram -> browser: forward the raw Flux JSON verbatim so the
                // frontend receives Deepgram's native wire format unchanged.
                dg.onMessage(raw -> {
                    try {
                        if (ctx.session.isOpen()) {
                            ctx.send(raw);
                        }
                    } catch (Exception e) {
                        System.err.println("Error forwarding Deepgram message to client: " + e.getMessage());
                    }
                });

                dg.onError(error -> {
                    System.err.println("Deepgram socket error: " + error.getMessage());
                    if (ctx.session.isOpen()) {
                        ctx.closeSession(1011, "Deepgram connection error");
                    }
                });

                dg.onDisconnected(reason -> {
                    System.out.println("Deepgram connection closed: " + reason.getCode() + " " + reason.getReason());
                    if (ctx.session.isOpen()) {
                        ctx.closeSession(getSafeCloseCode(reason.getCode()),
                                reason.getReason() != null ? reason.getReason() : "");
                    }
                });

                System.out.println("Connecting to Deepgram Flux (SDK Listen v2)");

                dg.connect(options).whenComplete((v, err) -> {
                    if (err != null) {
                        System.err.println("Deepgram connection failed to open: " + err.getMessage());
                        if (ctx.session.isOpen()) {
                            ctx.closeSession(1011, "Failed to connect to Deepgram");
                        }
                        return;
                    }
                    System.out.println("Connected to Deepgram Flux API");
                    bridge.markReady();
                });
            } catch (Exception e) {
                System.err.println("Failed to connect to Deepgram: " + e.getMessage());
                ctx.closeSession(1011, "Failed to connect to Deepgram");
            }
        });

        // Forward client control messages (JSON) to Deepgram
        ws.onMessage(ctx -> {
            FluxBridge bridge = ctx.attribute("bridge");
            if (bridge == null) return;
            try {
                JsonNode msg = objectMapper.readTree(ctx.message());
                String type = msg.path("type").asText("");
                if ("CloseStream".equals(type)) {
                    bridge.closeStream();
                } else {
                    System.out.println("Ignoring client control message type: " + type);
                }
            } catch (Exception e) {
                System.err.println("Ignoring non-JSON message from client");
            }
        });

        // Forward client binary audio to Deepgram
        ws.onBinaryMessage(ctx -> {
            FluxBridge bridge = ctx.attribute("bridge");
            if (bridge == null) return;
            byte[] data = ctx.data();
            int offset = ctx.offset();
            int length = ctx.length();
            bridge.sendAudio(ByteString.of(data, offset, length));
        });

        // Handle client disconnect
        ws.onClose(ctx -> {
            int code = ctx.status();
            String reason = ctx.reason() != null ? ctx.reason() : "";
            System.out.println("Client disconnected: " + code + " " + reason);

            FluxBridge bridge = ctx.attribute("bridge");
            if (bridge != null) {
                bridge.disconnect();
            }
            activeConnections.remove(ctx);
        });

        // Handle client errors
        ws.onError(ctx -> {
            Throwable error = ctx.error();
            if (error != null) {
                System.err.println("Client WebSocket error: " + error.getMessage());
            }
            FluxBridge bridge = ctx.attribute("bridge");
            if (bridge != null) {
                bridge.disconnect();
            }
            activeConnections.remove(ctx);
        });
    }

    // ========================================================================
    // SECTION 10: SERVER START
    // ========================================================================

    /**
     * Application entry point. Loads configuration, validates the API key,
     * initializes the Deepgram SDK client, and starts the Javalin server.
     *
     * @param args Command-line arguments (unused)
     */
    public static void main(String[] args) {
        // Load API key (exits if missing)
        apiKey = loadApiKey();

        // Build the Deepgram SDK client. DEEPGRAM_BASE_URL (e.g. a staging host
        // like wss://api.staging.deepgram.com) overrides the default production
        // endpoint used for the /v2/listen Flux websocket.
        var builder = DeepgramClient.builder().apiKey(apiKey);
        String baseUrl = getEnv("DEEPGRAM_BASE_URL", null);
        if (baseUrl != null && !baseUrl.isEmpty()) {
            String https = baseUrl.replaceFirst("^wss://", "https://").replaceFirst("^ws://", "http://");
            builder.environment(Environment.custom()
                    .base(https)
                    .production(baseUrl)
                    .agent(baseUrl)
                    .agentRest(https)
                    .build());
            System.out.println("Using custom Deepgram base URL: " + baseUrl);
        }
        deepgram = builder.build();

        // Create Javalin app with CORS enabled
        Javalin app = Javalin.create(config -> {
            config.bundledPlugins.enableCors(cors -> {
                cors.addRule(rule -> {
                    rule.anyHost();
                });
            });
        });

        // Session route (unprotected)
        app.get("/api/session", App::handleSession);

        // Metadata route (unprotected)
        app.get("/api/metadata", App::handleMetadata);

        // Health check route (unprotected)
        app.get("/health", ctx -> {
            ctx.json(Map.of("status", "ok"));
        });

        // WebSocket bridge route (authenticated via subprotocol)
        app.ws("/api/flux", App::handleFluxWebSocket);

        // Graceful shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Shutting down...");

            // Close all active client WebSocket connections
            System.out.println("Closing " + activeConnections.size() + " active connection(s)...");
            for (WsContext wsCtx : activeConnections) {
                try {
                    wsCtx.closeSession(1001, "Server shutting down");
                } catch (Exception e) {
                    System.err.println("Error closing WebSocket: " + e.getMessage());
                }
            }

            System.out.println("Shutdown complete");
        }));

        // Start the server
        app.start(HOST, PORT);

        String separator = "=".repeat(70);
        System.out.println();
        System.out.println(separator);
        System.out.println("  Backend API running at http://localhost:" + PORT);
        System.out.println("  GET  /api/session");
        System.out.println("  WS   /api/flux (auth required)");
        System.out.println("  GET  /api/metadata");
        System.out.println("  GET  /health");
        System.out.println(separator);
        System.out.println();
    }
}
