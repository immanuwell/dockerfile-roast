local M = {}

M.namespace = vim.api.nvim_create_namespace("droast")

M.config = {
  command = "droast",
  args = {},
  on_save = true,
  virtual_text = true,
  signs = true,
  underline = true,
}

local severity = {
  ERROR = vim.diagnostic.severity.ERROR,
  WARN = vim.diagnostic.severity.WARN,
  INFO = vim.diagnostic.severity.INFO,
}

local function diagnostic_from_finding(finding)
  local line = math.max((finding.line or 1) - 1, 0)
  local column = math.max((finding.column or 1) - 1, 0)
  local diagnostic = {
    lnum = line,
    col = column,
    severity = severity[finding.severity] or vim.diagnostic.severity.WARN,
    source = "droast",
    code = finding.rule,
    message = string.format("[%s] %s", finding.rule, finding.message),
  }
  if finding.end_line then
    diagnostic.end_lnum = math.max(finding.end_line - 1, line)
  end
  if finding.end_column then
    diagnostic.end_col = math.max(finding.end_column - 1, column)
  end
  return diagnostic
end

local function publish(bufnr, payload)
  local diagnostics = {}
  for _, finding in ipairs(payload.findings or {}) do
    table.insert(diagnostics, diagnostic_from_finding(finding))
  end
  vim.diagnostic.set(M.namespace, bufnr, diagnostics, {
    virtual_text = M.config.virtual_text,
    signs = M.config.signs,
    underline = M.config.underline,
  })
  return diagnostics
end

---Lint one file asynchronously and publish the result as Neovim diagnostics.
---@param bufnr? integer
---@param on_complete? fun(diagnostics: table[])
function M.lint(bufnr, on_complete)
  bufnr = bufnr or vim.api.nvim_get_current_buf()
  local filename = vim.api.nvim_buf_get_name(bufnr)
  if filename == "" then
    vim.notify("droast: save the buffer before linting it", vim.log.levels.WARN)
    return
  end

  local changedtick = vim.api.nvim_buf_get_changedtick(bufnr)
  local stdout = {}
  local stderr = {}
  local command = vim.list_extend({ M.config.command }, M.config.args)
  vim.list_extend(command, {
    "--format", "json", "--no-roast", "--no-fail", "--check-dockerignore=false", filename,
  })

  local job = vim.fn.jobstart(command, {
    stdout_buffered = true,
    stderr_buffered = true,
    on_stdout = function(_, data)
      stdout = data or {}
    end,
    on_stderr = function(_, data)
      stderr = data or {}
    end,
    on_exit = function(_, code)
      vim.schedule(function()
        if not vim.api.nvim_buf_is_valid(bufnr) or vim.api.nvim_buf_get_changedtick(bufnr) ~= changedtick then
          return
        end
        local raw = table.concat(stdout, "\n")
        local ok, payload = pcall(vim.json.decode, raw)
        if code ~= 0 or not ok or type(payload) ~= "table" then
          local detail = table.concat(stderr, "\n")
          if detail == "" then detail = "invalid JSON output" end
          vim.notify("droast failed: " .. detail, vim.log.levels.ERROR)
          return
        end
        local diagnostics = publish(bufnr, payload)
        if on_complete then on_complete(diagnostics) end
      end)
    end,
  })
  if job <= 0 then
    vim.notify("droast: cannot start '" .. M.config.command .. "'", vim.log.levels.ERROR)
  end
end

function M.quickfix()
  local filename = vim.api.nvim_buf_get_name(0)
  M.lint(0, function(diagnostics)
    local items = {}
    for _, diagnostic in ipairs(diagnostics) do
      table.insert(items, {
        filename = filename,
        lnum = diagnostic.lnum + 1,
        col = diagnostic.col + 1,
        type = diagnostic.severity == vim.diagnostic.severity.ERROR and "E" or "W",
        text = diagnostic.message,
      })
    end
    vim.fn.setqflist({}, " ", { title = "droast", items = items })
    vim.cmd.copen()
  end)
end

function M.setup(options)
  M.config = vim.tbl_deep_extend("force", M.config, options or {})
  vim.api.nvim_create_user_command("DroastLint", function() M.lint() end, {})
  vim.api.nvim_create_user_command("DroastQuickfix", M.quickfix, {})
  local group = vim.api.nvim_create_augroup("droast", { clear = true })
  if M.config.on_save then
    vim.api.nvim_create_autocmd("BufWritePost", {
      group = group,
      pattern = { "Dockerfile", "Dockerfile.*", "*.Dockerfile", "Containerfile", "Containerfile.*" },
      callback = function(args) M.lint(args.buf) end,
    })
  end
end

return M
