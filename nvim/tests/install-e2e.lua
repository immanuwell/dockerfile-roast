local root = vim.env.DROAST_REPO_ROOT
local plugin_root = vim.env.DROAST_INSTALLED_PLUGIN_ROOT
assert(root and plugin_root, "test paths are required")
vim.opt.rtp:append(plugin_root)
vim.cmd("runtime plugin/droast.lua")
assert(vim.fn.exists(":DroastLint") == 2, "installed plugin did not configure itself")

local droast = require("droast")
droast.setup({ command = root .. "/target/release/droast", args = { "--only", "DF002" } })
local dockerfile = vim.fn.tempname() .. ".Dockerfile"
vim.fn.writefile({ "FROM alpine:3.20", "USER root" }, dockerfile)
vim.cmd.edit(vim.fn.fnameescape(dockerfile))
droast.lint(0)
assert(vim.wait(5000, function()
  return #vim.diagnostic.get(0, { namespace = droast.namespace }) == 1
end, 10), "installed plugin diagnostics did not arrive")
assert(vim.diagnostic.get(0, { namespace = droast.namespace })[1].code == "DF002")
vim.cmd("qa!")
