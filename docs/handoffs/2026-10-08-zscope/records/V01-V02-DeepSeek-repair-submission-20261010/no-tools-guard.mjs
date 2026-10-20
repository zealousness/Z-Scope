export const name = "v01-v02-no-tools-guard";
export const inject = ["tools"];
export function apply(ctx) {
  ctx.tools.guard(() => "This approved repair session accepts only supplied source/test text and returns a patch. Filesystem, process, web, plugin, and agent tool execution is disabled.");
  ctx.provide("taskNoToolsGuard", true);
}

