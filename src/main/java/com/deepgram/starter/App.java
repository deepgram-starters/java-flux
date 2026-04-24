/**
 * Java Flux Starter - Backend Server
 *
 * Simple WebSocket proxy to Deepgram's Flux API using the Deepgram Java SDK.
 * Forwards audio from the browser to the SDK's V2 WebSocket client, and
 * forwards transcription events back to the browser.
 *
 * Key Features:
 * - WebSocket proxy endpoint: /api/flux -> Deepgram V2 Listen WebSocket
 * - JWT session auth via access_token.<jwt> subprotocol
 * - Session endpoint: GET /api/session
 * - Metadata endpoint: GET /api/metadata
 * - Uses Deepgram Java SDK for WebSocket connection management
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
import com.deepgram.resources.listen.v2.websocket.V2WebSocketClient;
import com.deepgram.resources.listen.v2.websocket.V2ConnectOptions;
import com.deepgram.types.ListenV2Encoding;
import com.deepgram.types.ListenV2SampleRate;

import okio.ByteString;

import java.io.File;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.Map;
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
        // Generate random 32 bytes as hex
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
     * Validates a JWT token from WebSocket subprotocol header.
     * The client sends "access_token.<jwt>" as a subprotocol.
     *
     * @param subprotocols The list of subprotocol strings from the upgrade request
     * @return true if token is valid, false otherwise
     */
    private static boolean validateWsToken(List<String> subprotocols) {
        for (String proto : subprotocols) {
            if (proto.startsWith("access_token.")) {
                String token = proto.substring("access_token.".length());
                try {
                    jwtVerifier.verify(token);
                    return true;
                } catch (JWTVerificationException e) {
                    return false;
                }
            }
        }
        return false;
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
    // SECTION 6: HELPER FUNCTIONS
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

    // ========================================================================
    // SECTION 7: TRACK ACTIVE WEBSOCKET CONNECTIONS
    // ========================================================================

    /** Map of browser WsContext -> SDK V2WebSocketClient for cleanup */
    private static final ConcurrentHashMap<WsContext, V2WebSocketClient> activeConnections =
            new ConcurrentHashMap<>();

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
    // SECTION 9: METADATA ROUTE
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

    // ========================================================================
    // SECTION 10: WEBSOCKET ROUTE - Flux Proxy
    // ========================================================================

    /**
     * Configures the WebSocket endpoint for Flux transcription.
     * Acts as a bidirectional proxy: browser <-> Javalin <-> Deepgram SDK V2 WebSocket.
     *
     * The SDK handles the outbound connection to Deepgram, authentication,
     * and WebSocket lifecycle. This handler bridges the browser's WebSocket
     * connection to the SDK's WebSocket client.
     *
     * @param ws Javalin WebSocket config
     */
    private static void handleFlux(WsConfig ws) {

        ws.onConnect(ctx -> {
            // Authenticate via subprotocol header
            List<String> subprotocols = ctx.header("Sec-WebSocket-Protocol") != null
                    ? List.of(ctx.header("Sec-WebSocket-Protocol").split(",\\s*"))
                    : List.of();

            if (!validateWsToken(subprotocols)) {
                ctx.closeSession(4001, "Unauthorized");
                return;
            }

            // Parse query params with defaults
            String model = ctx.queryParam("model") != null ? ctx.queryParam("model") : "flux-general-en";
            String encoding = ctx.queryParam("encoding") != null ? ctx.queryParam("encoding") : "linear16";
            String sampleRate = ctx.queryParam("sample_rate") != null ? ctx.queryParam("sample_rate") : "16000";

            // Create SDK client for this connection
            DeepgramClient dgClient = DeepgramClient.builder()
                    .apiKey(apiKey)
                    .build();

            V2WebSocketClient dgWs = dgClient.listen().v2().v2WebSocket();

            // Forward all text messages (transcripts/events) from Deepgram to browser
            dgWs.onMessage(json -> {
                try {
                    if (ctx.session.isOpen()) {
                        ctx.send(json);
                    }
                } catch (Exception e) {
                    System.err.println("Error forwarding transcript to browser: " + e.getMessage());
                }
            });

            dgWs.onError(e -> {
                System.err.println("Deepgram WebSocket error: " + e.getMessage());
                try {
                    if (ctx.session.isOpen()) {
                        ctx.closeSession(1011, "Deepgram connection error");
                    }
                } catch (Exception ignored) {}
            });

            dgWs.onDisconnected(reason -> {
                try {
                    if (ctx.session.isOpen()) {
                        ctx.closeSession(1000, "Deepgram disconnected");
                    }
                } catch (Exception ignored) {}
                activeConnections.remove(ctx);
            });

            // Build connection options using SDK builder
            V2ConnectOptions.Builder optionsBuilder = (V2ConnectOptions.Builder)
                    V2ConnectOptions.builder()
                            .model(model);
            optionsBuilder
                    .encoding(ListenV2Encoding.valueOf(encoding))
                    .sampleRate(ListenV2SampleRate.of(Integer.parseInt(sampleRate)));
            V2ConnectOptions options = optionsBuilder.build();

            // Connect to Deepgram via SDK
            dgWs.connect(options).thenRun(() -> {
                activeConnections.put(ctx, dgWs);
                System.out.println("Flux session started (model=" + model + ")");
            }).exceptionally(e -> {
                System.err.println("Failed to connect to Deepgram: " + e.getMessage());
                try {
                    ctx.closeSession(1011, "Failed to connect to Deepgram");
                } catch (Exception ignored) {}
                return null;
            });
        });

        // Forward audio binary from browser to Deepgram via SDK
        ws.onBinaryMessage(ctx -> {
            V2WebSocketClient dgWs = activeConnections.get(ctx);
            if (dgWs != null) {
                byte[] data = ctx.data();
                int offset = ctx.offset();
                int length = ctx.length();
                byte[] audioData = new byte[length];
                System.arraycopy(data, offset, audioData, 0, length);
                dgWs.sendMedia(ByteString.of(audioData));
            }
        });

        // Handle client disconnect - clean up Deepgram connection
        ws.onClose(ctx -> {
            V2WebSocketClient dgWs = activeConnections.remove(ctx);
            if (dgWs != null) {
                try {
                    dgWs.disconnect();
                } catch (Exception ignored) {}
            }
            System.out.println("Flux session ended");
        });

        // Handle client errors
        ws.onError(ctx -> {
            V2WebSocketClient dgWs = activeConnections.remove(ctx);
            if (dgWs != null) {
                try {
                    dgWs.disconnect();
                } catch (Exception ignored) {}
            }
        });
    }

    // ========================================================================
    // SECTION 11: SERVER START
    // ========================================================================

    /**
     * Application entry point. Loads configuration, validates the API key,
     * and starts the Javalin HTTP server with WebSocket support.
     *
     * @param args Command-line arguments (unused)
     */
    public static void main(String[] args) {
        // Load API key (exits if missing)
        apiKey = loadApiKey();

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

        // WebSocket route for Flux transcription (auth via subprotocol)
        app.ws("/api/flux", App::handleFlux);

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
