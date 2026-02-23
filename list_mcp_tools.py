import sys
import asyncio
import json

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:
    print("mcp module not found.")
    sys.exit(1)

SERVER_CMD = r"C:\Users\rodri\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\LocalCache\local-packages\Python313\Scripts\notebooklm-mcp.exe"

async def main():
    async with stdio_client(StdioServerParameters(command=SERVER_CMD, args=[], env=None)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            print("--- TOOLS ---")
            tools = await session.list_tools()
            for t in tools.tools:
                print(f"Name: {t.name}")
                print(f"Description: {t.description}")
                print("-" * 20)

            print("\n--- RESOURCES ---")
            try:
                resources = await session.list_resources()
                for r in resources.resources:
                    print(f"URI: {r.uri}")
                    print(f"Name: {r.name}")
            except Exception as e:
                print(f"No resources or error: {e}")

            print("\n--- PROMPTS ---")
            try:
                prompts = await session.list_prompts()
                for p in prompts.prompts:
                    print(f"Name: {p.name}")
                    print(f"Description: {p.description}")
            except Exception as e:
                print(f"No prompts or error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
