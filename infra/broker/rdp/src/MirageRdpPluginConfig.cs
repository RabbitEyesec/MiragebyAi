using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Mirage.RdpSteering
{
    /// <summary>
    /// Mirrors config/rdp-plugin-config.schema.json exactly — that JSON
    /// Schema is the single source of truth for what this config file must
    /// contain; keep the two in sync by hand (this project has no schema
    /// codegen step of its own, unlike the Python/TypeScript contracts).
    /// </summary>
    public sealed class MirageRdpPluginConfig
    {
        [JsonPropertyName("mirage_api_url")]
        public string MirageApiUrl { get; set; } = string.Empty;

        [JsonPropertyName("gateway_listener_id")]
        public string GatewayListenerId { get; set; } = string.Empty;

        [JsonPropertyName("client_cert_path")]
        public string ClientCertPath { get; set; } = string.Empty;

        [JsonPropertyName("client_key_path")]
        public string ClientKeyPath { get; set; } = string.Empty;

        [JsonPropertyName("root_ca_path")]
        public string RootCaPath { get; set; } = string.Empty;

        [JsonPropertyName("client_cert_serial")]
        public string ClientCertSerial { get; set; } = string.Empty;

        [JsonPropertyName("proxy_shared_secret_env_var")]
        public string ProxySharedSecretEnvVar { get; set; } = string.Empty;

        [JsonPropertyName("timeout_ms")]
        public int TimeoutMs { get; set; } = 2000;

        [JsonPropertyName("fail_safe_target")]
        public string FailSafeTarget { get; set; } = "ENDPOINT";

        [JsonPropertyName("event_log_source")]
        public string EventLogSource { get; set; } = "MirageRdpPlugin";

        /// <summary>
        /// Reads the proxy shared secret from the environment variable this
        /// config names — the secret VALUE is never present in the config
        /// file itself (docs/runbooks/secrets.md's rule: secret values
        /// never committed, never baked into a package).
        /// </summary>
        public string ResolveProxySharedSecret()
        {
            string? value = Environment.GetEnvironmentVariable(ProxySharedSecretEnvVar);
            if (string.IsNullOrEmpty(value))
            {
                throw new InvalidOperationException(
                    $"environment variable '{ProxySharedSecretEnvVar}' (named by proxy_shared_secret_env_var) is not set or empty");
            }
            return value;
        }

        public static MirageRdpPluginConfig LoadFromFile(string path)
        {
            string json = File.ReadAllText(path);
            MirageRdpPluginConfig? config = JsonSerializer.Deserialize<MirageRdpPluginConfig>(json);
            if (config is null)
            {
                throw new InvalidOperationException($"config file '{path}' did not deserialize to a valid config object");
            }
            config.Validate();
            return config;
        }

        public void Validate()
        {
            void Require(string value, string fieldName)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new InvalidOperationException($"config field '{fieldName}' is required and must be non-empty");
                }
            }

            Require(MirageApiUrl, nameof(MirageApiUrl));
            Require(GatewayListenerId, nameof(GatewayListenerId));
            Require(ClientCertPath, nameof(ClientCertPath));
            Require(ClientKeyPath, nameof(ClientKeyPath));
            Require(RootCaPath, nameof(RootCaPath));
            Require(ClientCertSerial, nameof(ClientCertSerial));
            Require(ProxySharedSecretEnvVar, nameof(ProxySharedSecretEnvVar));
            Require(EventLogSource, nameof(EventLogSource));

            if (TimeoutMs < 100 || TimeoutMs > 10000)
            {
                throw new InvalidOperationException($"config field '{nameof(TimeoutMs)}' must be between 100 and 10000");
            }
            if (FailSafeTarget != "ENDPOINT" && FailSafeTarget != "DENY")
            {
                throw new InvalidOperationException(
                    $"config field '{nameof(FailSafeTarget)}' must be 'ENDPOINT' or 'DENY', never 'SANDBOX' — a broker must never fail open into the observed environment");
            }
        }
    }
}
