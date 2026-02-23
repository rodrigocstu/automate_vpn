# MCP Configuration Guide / Guía de Configuración MCP

This guide explains how to use the provided MCP configuration.
Esta guía explica cómo utilizar la configuración MCP proporcionada.

## English

The file `mcp_config.json` contains the configuration for the "stitch" MCP server. To use this with an MCP-compatible client (like Claude Desktop or others):

1.  **Locate your client's configuration file.** For Claude Desktop on Windows, it is typically at `%APPDATA%\Claude\claude_desktop_config.json`.
2.  **Add the server configuration.** Copy the content of `mcp_config.json` into your client's configuration file. If the file already exists, merge the `mcpServers` object.

Example structure:
```json
{
  "mcpServers": {
    "stitch": {
      "serverUrl": "https://stitch.googleapis.com/mcp",
      "headers": {
        "X-Goog-Api-Key": "YOUR_API_KEY_HERE"
      }
    }
    // ... other servers
  }
}
```

## Español

El archivo `mcp_config.json` contiene la configuración para el servidor MCP "stitch". Para usar esto con un cliente compatible con MCP (como Claude Desktop u otros):

1.  **Localiza el archivo de configuración de tu cliente.** Para Claude Desktop en Windows, típicamente está en `%APPDATA%\Claude\claude_desktop_config.json`.
2.  **Agrega la configuración del servidor.** Copia el contenido de `mcp_config.json` en el archivo de configuración de tu cliente. Si el archivo ya existe, fusiona el objeto `mcpServers`.

Estructura de ejemplo:
```json
{
  "mcpServers": {
    "stitch": {
      "serverUrl": "https://stitch.googleapis.com/mcp",
      "headers": {
        "X-Goog-Api-Key": "TU_CLAVE_API_AQUI"
      }
    }
    // ... otros servidores
  }
}
```
