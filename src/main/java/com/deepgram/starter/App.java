/**
 * Java Flux Starter - Backend Server
 *
 * Simple WebSocket proxy to Deepgram's Flux API using Javalin 6.4.0.
 * Forwards all messages (JSON and binary) bidirectionally between client and Deepgram.
 *
 * Key Features:
 * - WebSocket proxy endpoint: /api/flux -> Deepgram wss://api.deepgram.com/v2/listen
 * - JWT session auth via access_token.<jwt> subprotocol
 * - Session endpoint: GET /api/session
 * - Metadata endpoint: GET /api/metadata
 * - No Deepgram SDK -- direct WebSocket connections via Jetty WebSocket client
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

import org.eclipse.jetty.websocket.api.Callback;
import org.eclipse.jetty.websocket.api.Session;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketClose;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketError;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketMessage;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketOpen;
import org.eclipse.jetty.websocket.api.annotations.WebSocket;
import org.eclipse.jetty.websocket.client.ClientUpgradeRequest;
import org.eclipse.jetty.websocket.client.WebSocketClient;

import java.io.File;
import java.net.URI;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Instant;
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

    /** Deepgram Flux WebSocket URL (v2 endpoint) */
    private static final String DEEPGRAM_FLUX_URL = "wss://api.deepgram.com/v2/listen";

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
    // SECTION 6: SETUP - Track connections and Jetty WebSocket client
    // ========================================================================

    /** Track all active client WebSocket contexts for graceful shutdown */
    private static final Set<WsContext> activeConnections = ConcurrentHashMap.newKeySet();

    /** Jetty WebSocket client for outbound connections to Deepgram */
    private static WebSocketClient wsClient;

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
     * Builds the Deepgram Flux WebSocket URL with query parameters forwarded from the client.
     *
     * @param ctx The client WebSocket context
     * @return The fully constructed Deepgram URL string
     */
    private static String buildDeepgramUrl(WsContext ctx) {
        String model = ctx.queryParam("model");
        if (model == null || model.isEmpty()) model = "flux-general-en";

        String sampleRate = ctx.queryParam("sample_rate");
        if (sampleRate == null || sampleRate.isEmpty()) sampleRate = "16000";

        String encoding = ctx.queryParam("encoding");
        if (encoding == null || encoding.isEmpty()) encoding = "linear16";

        String channels = ctx.queryParam("channels");
        if (channels == null || channels.isEmpty()) channels = "1";

        StringBuilder url = new StringBuilder(DEEPGRAM_FLUX_URL);
        url.append("?model=").append(model);
        url.append("&sample_rate=").append(sampleRate);
        url.append("&encoding=").append(encoding);
        url.append("&channels=").append(channels);

        // Forward optional parameters
        String eotThreshold = ctx.queryParam("eot_threshold");
        if (eotThreshold != null && !eotThreshold.isEmpty()) {
            url.append("&eot_threshold=").append(eotThreshold);
        }

        String eagerEotThreshold = ctx.queryParam("eager_eot_threshold");
        if (eagerEotThreshold != null && !eagerEotThreshold.isEmpty()) {
            url.append("&eager_eot_threshold=").append(eagerEotThreshold);
        }

        String eotTimeoutMs = ctx.queryParam("eot_timeout_ms");
        if (eotTimeoutMs != null && !eotTimeoutMs.isEmpty()) {
            url.append("&eot_timeout_ms=").append(eotTimeoutMs);
        }

        // Handle keyterm: can appear multiple times, forward each one
        List<String> keyterms = ctx.queryParams("keyterm");
        if (keyterms != null) {
            for (String term : keyterms) {
                if (term != null && !term.isEmpty()) {
                    url.append("&keyterm=").append(term);
                }
            }
        }

        return url.toString();
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
    // SECTION 9: API ROUTES & WEBSOCKET PROXY
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
     * Configures the /api/flux WebSocket endpoint.
     * Validates JWT from subprotocol on upgrade, then creates a bidirectional
     * proxy to Deepgram's Flux API.
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

            // Build the Deepgram URL with forwarded query parameters
            String deepgramUrl = buildDeepgramUrl(ctx);
            System.out.println("Connecting to Deepgram Flux: " + deepgramUrl);

            // Create outbound WebSocket connection to Deepgram
            try {
                ClientUpgradeRequest upgradeRequest = new ClientUpgradeRequest();
                upgradeRequest.setHeader("Authorization", "Token " + apiKey);

                DeepgramSocket dgSocket = new DeepgramSocket(ctx);
                // Store the Deepgram socket on the ctx attribute map for forwarding
                ctx.attribute("deepgramSocket", dgSocket);

                wsClient.connect(dgSocket, URI.create(deepgramUrl), upgradeRequest);
            } catch (Exception e) {
                System.err.println("Failed to connect to Deepgram: " + e.getMessage());
                ctx.closeSession(1011, "Failed to connect to Deepgram");
            }
        });

        // Forward client messages to Deepgram
        ws.onMessage(ctx -> {
            DeepgramSocket dgSocket = ctx.attribute("deepgramSocket");
            if (dgSocket != null && dgSocket.isOpen()) {
                String text = ctx.message();
                dgSocket.sendText(text);
            }
        });

        // Forward client binary messages to Deepgram
        ws.onBinaryMessage((ctx, data, offset, length) -> {
            DeepgramSocket dgSocket = ctx.attribute("deepgramSocket");
            if (dgSocket != null && dgSocket.isOpen()) {
                ByteBuffer buffer = ByteBuffer.wrap(data, offset, length);
                dgSocket.sendBinary(buffer);
            }
        });

        // Handle client disconnect
        ws.onClose(ctx -> {
            int code = ctx.status();
            String reason = ctx.reason() != null ? ctx.reason() : "";
            System.out.println("Client disconnected: " + code + " " + reason);

            DeepgramSocket dgSocket = ctx.attribute("deepgramSocket");
            if (dgSocket != null && dgSocket.isOpen()) {
                dgSocket.close(1000, "Client disconnected");
            }
            activeConnections.remove(ctx);
        });

        // Handle client errors
        ws.onError(ctx -> {
            Throwable error = ctx.error();
            if (error != null) {
                System.err.println("Client WebSocket error: " + error.getMessage());
            }
            DeepgramSocket dgSocket = ctx.attribute("deepgramSocket");
            if (dgSocket != null && dgSocket.isOpen()) {
                dgSocket.close(1011, "Client error");
            }
            activeConnections.remove(ctx);
        });
    }

    /**
     * Jetty WebSocket endpoint for the outbound connection to Deepgram.
     * Forwards all messages from Deepgram back to the connected client.
     */
    @WebSocket
    public static class DeepgramSocket {

        /** Reference to the client-side WsContext for forwarding messages */
        private final WsContext clientCtx;

        /** The Deepgram-side Jetty WebSocket session */
        private volatile Session deepgramSession;

        /** Message counters for debug logging */
        private int clientMessageCount = 0;
        private int deepgramMessageCount = 0;

        public DeepgramSocket(WsContext clientCtx) {
            this.clientCtx = clientCtx;
        }

        @OnWebSocketOpen
        public void onOpen(Session session) {
            this.deepgramSession = session;
            System.out.println("Connected to Deepgram Flux API");
        }

        /**
         * Forwards text messages from Deepgram to the client.
         */
        @OnWebSocketMessage
        public void onTextMessage(Session session, String message) {
            deepgramMessageCount++;
            if (deepgramMessageCount % 10 == 0) {
                System.out.println("<- Deepgram text message #" + deepgramMessageCount
                        + " (size: " + message.length() + ")");
            }
            try {
                if (clientCtx.session.isOpen()) {
                    clientCtx.send(message);
                }
            } catch (Exception e) {
                System.err.println("Error forwarding Deepgram text to client: " + e.getMessage());
            }
        }

        /**
         * Forwards binary messages from Deepgram to the client.
         */
        @OnWebSocketMessage
        public void onBinaryMessage(Session session, ByteBuffer payload, Callback callback) {
            deepgramMessageCount++;
            if (deepgramMessageCount % 10 == 0) {
                System.out.println("<- Deepgram binary message #" + deepgramMessageCount
                        + " (size: " + payload.remaining() + ")");
            }
            try {
                if (clientCtx.session.isOpen()) {
                    byte[] data = new byte[payload.remaining()];
                    payload.get(data);
                    clientCtx.send(ByteBuffer.wrap(data));
                }
                callback.succeed();
            } catch (Exception e) {
                System.err.println("Error forwarding Deepgram binary to client: " + e.getMessage());
                callback.fail(e);
            }
        }

        @OnWebSocketClose
        public void onClose(int statusCode, String reason) {
            System.out.println("Deepgram connection closed: " + statusCode + " " + reason);
            try {
                if (clientCtx.session.isOpen()) {
                    int safeCode = getSafeCloseCode(statusCode);
                    clientCtx.closeSession(safeCode, reason != null ? reason : "");
                }
            } catch (Exception e) {
                System.err.println("Error closing client after Deepgram close: " + e.getMessage());
            }
        }

        @OnWebSocketError
        public void onError(Throwable cause) {
            System.err.println("Deepgram WebSocket error: " + cause.getMessage());
            try {
                if (clientCtx.session.isOpen()) {
                    clientCtx.closeSession(1011, "Deepgram connection error");
                }
            } catch (Exception e) {
                System.err.println("Error closing client after Deepgram error: " + e.getMessage());
            }
        }

        /** Check if the Deepgram connection is open */
        public boolean isOpen() {
            return deepgramSession != null && deepgramSession.isOpen();
        }

        /** Send text data to Deepgram */
        public void sendText(String text) {
            clientMessageCount++;
            if (clientMessageCount % 100 == 0) {
                System.out.println("-> Client text message #" + clientMessageCount
                        + " (size: " + text.length() + ")");
            }
            if (isOpen()) {
                deepgramSession.sendText(text, Callback.NOOP);
            }
        }

        /** Send binary data to Deepgram */
        public void sendBinary(ByteBuffer data) {
            clientMessageCount++;
            if (clientMessageCount % 100 == 0) {
                System.out.println("-> Client binary message #" + clientMessageCount
                        + " (size: " + data.remaining() + ")");
            }
            if (isOpen()) {
                deepgramSession.sendBinary(data, Callback.NOOP);
            }
        }

        /** Close the Deepgram connection */
        public void close(int code, String reason) {
            if (isOpen()) {
                deepgramSession.close(code, reason, Callback.NOOP);
            }
        }
    }

    // ========================================================================
    // SECTION 10: SERVER START
    // ========================================================================

    /**
     * Application entry point. Loads configuration, validates the API key,
     * initializes the Jetty WebSocket client, and starts the Javalin server.
     *
     * @param args Command-line arguments (unused)
     */
    public static void main(String[] args) {
        // Load API key (exits if missing)
        apiKey = loadApiKey();

        // Initialize Jetty WebSocket client for outbound Deepgram connections
        wsClient = new WebSocketClient();
        try {
            wsClient.start();
        } catch (Exception e) {
            System.err.println("Failed to start WebSocket client: " + e.getMessage());
            System.exit(1);
        }

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

        // WebSocket proxy route (authenticated via subprotocol)
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

            // Stop the Jetty WebSocket client
            try {
                wsClient.stop();
            } catch (Exception e) {
                System.err.println("Error stopping WebSocket client: " + e.getMessage());
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
