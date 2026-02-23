import sys
import asyncio
import json

# Try importing mcp
try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:
    print("mcp module not found. Please ensure it is installed.")
    sys.exit(1)

SERVER_CMD = r"C:\Users\rodri\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\LocalCache\local-packages\Python313\Scripts\notebooklm-mcp.exe"

async def main():
    print(f"Connecting to server: {SERVER_CMD}")
    async with stdio_client(StdioServerParameters(command=SERVER_CMD, args=[], env=None)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # 1. List Tools
            print("\nListing tools...")
            tools_result = await session.list_tools()
            tools = tools_result.tools
            count = len(tools)
            print(f"Total tools found: {count}")
            
            create_tool = None
            list_tool = None
            
            for t in tools:
                # specific check for create notebook
                if "create_notebook" in t.name or ("create" in t.name and "notebook" in t.name):
                    create_tool = t.name
                if "list_notebooks" in t.name or ("list" in t.name and "notebook" in t.name):
                    list_tool = t.name
                    
            if count >= 32:
                print("PASS: Tool count >= 32")
            else:
                print(f"FAIL: Tool count {count} < 32")

            if create_tool:
                print(f"PASS: Create notebook tool found: {create_tool}")
            else:
                print("FAIL: Create notebook tool NOT found")

            # 2. Functional Test: List Notebooks
            if list_tool:
                print(f"\nRunning functional test: {list_tool}...")
                try:
                    result = await session.call_tool(list_tool, arguments={})
                    print("Result:")
                    # print(json.dumps(result, indent=2, default=str))
                    # Check text content
                    for content in result.content:
                        if content.type == 'text':
                            print(content.text)
                except Exception as e:
                    print(f"Error calling tool: {e}")
            else:
                print("Skipping functional test (list tool not found)")

if __name__ == "__main__":
    asyncio.run(main())
