local root = vim.env.DROAST_REPO_ROOT
assert(root and root ~= "", "DROAST_REPO_ROOT must point to the repository root")
vim.opt.rtp:append(root .. "/nvim")

local droast = require("droast")
droast.setup({
  command = root .. "/target/release/droast",
  args = { "--only", "DF002" },
  on_save = false,
  virtual_text = false,
})

local dockerfile = vim.fn.tempname() .. ".Dockerfile"
vim.fn.writefile({ "FROM alpine:3.20", "USER root" }, dockerfile)
vim.cmd.edit(vim.fn.fnameescape(dockerfile))
droast.lint(0)
assert(vim.wait(5000, function()
  return #vim.diagnostic.get(0, { namespace = droast.namespace }) == 1
end, 10), "droast diagnostics did not arrive")

local diagnostic = vim.diagnostic.get(0, { namespace = droast.namespace })[1]
assert(diagnostic.code == "DF002", "expected DF002 diagnostic")
assert(diagnostic.lnum == 1 and diagnostic.col == 0, "diagnostic location was not preserved")
vim.cmd("qa!")
