# droast.nvim

Native Neovim diagnostics for [Droast](https://github.com/immanuwell/dockerfile-roast).
Requires Neovim 0.9+ and the `droast` executable on `PATH`.

## Install

Install the bundled extension without a plugin manager:

```bash
curl -fsSL https://raw.githubusercontent.com/immanuwell/dockerfile-roast/main/scripts/install-neovim-extension.sh | sh
```

Or use the dedicated plugin repository with your preferred manager:

```lua
-- lazy.nvim
{ "immanuwell/droast.nvim" }

-- packer.nvim
use "immanuwell/droast.nvim"

-- mini.deps
MiniDeps.add({ source = "immanuwell/droast.nvim" })
```

The plugin starts with sensible defaults. Override them after installation:

```lua
require("droast").setup({
  command = "droast",
  on_save = true,
  args = { "--preset", "production" },
})
```

Use `:DroastLint` for the current buffer or `:DroastQuickfix` to populate the
quickfix list.
