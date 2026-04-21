#!/usr/bin/env node
// MCP server exposing the local-test helpers for LLNG plugins.
// Core logic lives in lib.js (shared with cli.js).

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import {
  cleanAll,
  cleanTest,
  executeTest,
  listPluginDirs,
  prepareTest,
} from "./lib.js";

const TOOLS = [
  {
    name: "list-plugins",
    description:
      "List plugins available in the plugins/ directory of this repository.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "prepare-test",
    description:
      "Clone LemonLDAP::NG into .llng-test/ (if needed), run `make common`, " +
      "and symlink the plugin's lib/, t/, portal-templates/, portal-static/, " +
      "manager-static/ into the LLNG tree, and merge portal-translations/ " +
      "into the portal's languages/ directory. Plugins declared in " +
      "`depends` (plugin.json) are linked transitively before the primary " +
      "plugin; use `with` to add extra dependencies and `noDeps` to disable " +
      "auto-resolution.",
    inputSchema: {
      type: "object",
      properties: {
        plugin: { type: "string", description: "Primary plugin name" },
        with: {
          type: "array",
          items: { type: "string" },
          description:
            "Extra plugins to link alongside the primary (lib + assets only; their tests are not linked).",
        },
        noDeps: {
          type: "boolean",
          default: false,
          description: "Skip auto-resolution of `depends` in plugin.json.",
        },
        skipMake: {
          type: "boolean",
          default: false,
          description: "Skip `make common` (useful on repeated runs).",
        },
      },
      required: ["plugin"],
      additionalProperties: false,
    },
  },
  {
    name: "execute-test",
    description:
      "Run `prove -v -I. -I../lemonldap-ng-common/blib/lib " +
      "-I../lemonldap-ng-handler/lib -I../lemonldap-ng-manager/lib " +
      "-I../lemonldap-ng-portal/lib` inside the primary plugin's LLNG " +
      "component directory. Requires prepare-test beforehand.",
    inputSchema: {
      type: "object",
      properties: {
        plugin: { type: "string", description: "Primary plugin name" },
        tests: {
          type: "array",
          items: { type: "string" },
          description:
            "Optional explicit test paths relative to the component dir (or absolute). Defaults to every .t in the plugin's t/.",
        },
        verbose: { type: "boolean", default: true },
      },
      required: ["plugin"],
      additionalProperties: false,
    },
  },
  {
    name: "clean-test",
    description:
      "Remove symlinks created inside the LLNG clone and un-merge any " +
      "translation keys that were added. Pass `plugin` or `plugins` to scope " +
      "the cleanup; omit both to clean every plugin. The LLNG clone itself is kept.",
    inputSchema: {
      type: "object",
      properties: {
        plugin: { type: "string", description: "Single plugin to clean." },
        plugins: {
          type: "array",
          items: { type: "string" },
          description: "Explicit list of plugins to clean.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "clean-all",
    description:
      "Full reset: remove every plugin symlink AND delete the .llng-test/ directory (including the LLNG clone). Use this to start from scratch.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "test",
    description:
      "Convenience: runs prepare-test then execute-test. Does not clean up.",
    inputSchema: {
      type: "object",
      properties: {
        plugin: { type: "string" },
        with: { type: "array", items: { type: "string" } },
        noDeps: { type: "boolean", default: false },
        skipMake: { type: "boolean", default: false },
        tests: { type: "array", items: { type: "string" } },
        verbose: { type: "boolean", default: true },
      },
      required: ["plugin"],
      additionalProperties: false,
    },
  },
];

function textResult(obj) {
  const text = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
  return { content: [{ type: "text", text }] };
}

function errorResult(err) {
  return {
    isError: true,
    content: [
      {
        type: "text",
        text: err instanceof Error ? err.stack || err.message : String(err),
      },
    ],
  };
}

const server = new Server(
  { name: "lemonldap-ng-plugins-mcp", version: "0.1.20" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args = {} } = req.params;
  try {
    switch (name) {
      case "list-plugins": {
        const plugins = await listPluginDirs();
        return textResult({ plugins, count: plugins.length });
      }
      case "prepare-test": {
        const res = await prepareTest(args.plugin, {
          skipMake: !!args.skipMake,
          with: args.with || [],
          noDeps: !!args.noDeps,
        });
        return textResult(res);
      }
      case "execute-test": {
        const res = await executeTest(args.plugin, {
          tests: args.tests,
          verbose: args.verbose !== false,
        });
        return textResult(res);
      }
      case "clean-test": {
        const scope = args.plugins
          ? args.plugins
          : args.plugin
            ? [args.plugin]
            : undefined;
        const res = await cleanTest({ plugins: scope });
        return textResult({
          removed: res.removed,
          removedCount: res.removed.length,
          translationKeysRemoved: res.unmerged,
        });
      }
      case "clean-all": {
        const res = await cleanAll();
        return textResult({
          removedCount: res.removed.length,
          translationKeysRemoved: res.unmerged,
          clonedRemoved: res.clonedRemoved,
          llngRoot: res.llngRoot,
        });
      }
      case "test": {
        const prep = await prepareTest(args.plugin, {
          skipMake: !!args.skipMake,
          with: args.with || [],
          noDeps: !!args.noDeps,
        });
        const exec = await executeTest(args.plugin, {
          tests: args.tests,
          verbose: args.verbose !== false,
        });
        return textResult({
          prepare: {
            primary: prep.primary,
            chain: prep.chain,
            component: prep.component,
            totals: prep.totals,
            log: prep.log,
          },
          execute: exec,
        });
      }
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (e) {
    return errorResult(e);
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
