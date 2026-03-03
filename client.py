import asyncio
import os
import sys

from anthropic import Anthropic
from dotenv import load_dotenv
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

load_dotenv()

GITHUB_OWNER = os.environ["GITHUB_OWNER"]
GITHUB_REPO = os.environ["GITHUB_REPO"]
GITHUB_BRANCH = os.environ["GITHUB_BRANCH"]

AGENT_PROMPT = f"""
Check dependencies of repository {GITHUB_OWNER}/{GITHUB_REPO} (branch: {GITHUB_BRANCH}) for vulnerabilities.

1. Fetch dependencies via get_dependencies
2. Check for CVEs via check_vulnerabilities
3. Read exceptions from org://exceptions and filter them out
4. If CRITICAL or HIGH vulnerabilities are found without exceptions:
   - Create a GitHub Issue with the report via create_github_issue
   - Return: FAIL with the list of issues
5. If everything is clean:
   - Return: PASS
"""

SERVER_PARAMS = StdioServerParameters(
    command=sys.executable,
    args=["server.py"],
    env={**os.environ},
)


async def run() -> int:
    anthropic = Anthropic()

    async with stdio_client(SERVER_PARAMS) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Collect available tools
            tools_result = await session.list_tools()
            tools = [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.inputSchema,
                }
                for t in tools_result.tools
            ]

            # Collect available resources
            resources_result = await session.list_resources()
            resource_contents = {}
            for resource in resources_result.resources:
                content = await session.read_resource(resource.uri)
                resource_contents[str(resource.uri)] = content.contents[0].text

            # Build system prompt with resource context
            system = "You are a security agent. Use the provided tools to check dependencies.\n\n"
            for uri, text in resource_contents.items():
                system += f"Resource {uri}:\n{text}\n\n"

            messages = [{"role": "user", "content": AGENT_PROMPT}]

            # Agentic loop
            while True:
                response = anthropic.messages.create(
                    model="claude-sonnet-4-6",
                    max_tokens=4096,
                    system=system,
                    tools=tools,
                    messages=messages,
                )

                # Append assistant response
                messages.append({"role": "assistant", "content": response.content})

                if response.stop_reason == "end_turn":
                    # Extract final text and determine exit code
                    final_text = next(
                        (b.text for b in response.content if hasattr(b, "text")),
                        "",
                    )
                    print(final_text)
                    return 0 if "PASS" in final_text else 1

                if response.stop_reason != "tool_use":
                    print(f"Unexpected stop reason: {response.stop_reason}", file=sys.stderr)
                    return 1

                # Execute tool calls
                tool_results = []
                for block in response.content:
                    if block.type != "tool_use":
                        continue
                    print(f"[tool] {block.name}({block.input})", file=sys.stderr)
                    result = await session.call_tool(block.name, block.input)
                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result.content[0].text,
                        }
                    )

                messages.append({"role": "user", "content": tool_results})


if __name__ == "__main__":
    sys.exit(asyncio.run(run()))
