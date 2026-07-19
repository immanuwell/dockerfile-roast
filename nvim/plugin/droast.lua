if vim.g.loaded_droast then return end
vim.g.loaded_droast = true

if vim.g.droast_auto_setup ~= false then
  require("droast").setup()
end
