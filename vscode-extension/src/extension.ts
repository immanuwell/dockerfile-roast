import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

// ── types matching droast --format json output ────────────────────────────────

interface Finding {
    rule: string;
    severity: 'ERROR' | 'WARN' | 'INFO';
    line: number;
    message: string;
    roast: string;
}

interface DroastOutput {
    file: string;
    findings: Finding[];
}

// ── state ─────────────────────────────────────────────────────────────────────

let diagnostics: vscode.DiagnosticCollection;
let log: vscode.OutputChannel;

// Pending debounce timers per document URI.
const timers = new Map<string, ReturnType<typeof setTimeout>>();

// Active droast processes per document URI — killed when a newer lint starts.
const procs = new Map<string, cp.ChildProcess>();

// ── activation ────────────────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext): void {
    log = vscode.window.createOutputChannel('droast');
    diagnostics = vscode.languages.createDiagnosticCollection('droast');
    context.subscriptions.push(log, diagnostics);

    context.subscriptions.push(
        // Use a small delay on open so that if activation already scheduled a
        // lint for this document, the debounce collapses them into one run.
        vscode.workspace.onDidOpenTextDocument(doc => scheduleLint(doc, 400)),
        vscode.workspace.onDidChangeTextDocument(e => scheduleLint(e.document)),
        vscode.workspace.onDidCloseTextDocument(doc => {
            const key = doc.uri.toString();
            clearTimer(key);
            killProc(key);
            diagnostics.delete(doc.uri);
        })
    );

    // Lint any Dockerfiles already open when the extension activates.
    vscode.workspace.textDocuments.forEach(doc => scheduleLint(doc, 0));
}

export function deactivate(): void {
    timers.forEach(clearTimeout);
    procs.forEach(p => p.kill());
    diagnostics?.dispose();
}

// ── debounce ──────────────────────────────────────────────────────────────────

function scheduleLint(doc: vscode.TextDocument, delay = 400): void {
    if (!isDockerfile(doc)) { return; }

    const config = vscode.workspace.getConfiguration('droast');
    if (!config.get<boolean>('enable', true)) { return; }

    const key = doc.uri.toString();
    clearTimer(key);
    timers.set(key, setTimeout(() => {
        timers.delete(key);
        runLint(doc);
    }, delay));
}

// ── core lint ─────────────────────────────────────────────────────────────────

function runLint(doc: vscode.TextDocument): void {
    const key = doc.uri.toString();
    killProc(key);

    const config  = vscode.workspace.getConfiguration('droast');
    const exe     = resolveExecutable(config.get<string>('executablePath', ''));
    const minSev  = config.get<string>('minSeverity', 'info');
    const skip    = config.get<string[]>('skipRules', []);
    const noRoast = config.get<boolean>('noRoast', false);


    const args: string[] = ['--format', 'json', '--min-severity', minSev];
    if (skip.length > 0) { args.push('--skip', skip.join(',')); }
    args.push('-');   // read from stdin

    let stdout = '';
    let stderr = '';

    const proc = cp.spawn(exe, args);
    procs.set(key, proc);

    proc.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString(); });
    proc.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });

    proc.on('error', (err: NodeJS.ErrnoException) => {
        procs.delete(key);
        if (err.code === 'ENOENT') {
            vscode.window.showErrorMessage(
                'droast not found. Install it with: curl -fsL ewry.net/droast/install.sh | sh',
                'Show install instructions'
            ).then(sel => {
                if (sel) {
                    vscode.env.openExternal(
                        vscode.Uri.parse('https://github.com/immanuwell/dockerfile-roast#install')
                    );
                }
            });
        }
    });

    proc.on('close', (code: number | null) => {
        procs.delete(key);
        // Exit code 1 means findings were found — that's expected, not an error.
        // Anything else (2, null) is a real failure.
        if (code !== 0 && code !== 1) { return; }
        if (!stdout.trim()) { return; }

        try {
            const output: DroastOutput = JSON.parse(stdout);
            const diags = output.findings.map(f => toDiagnostic(f, doc, noRoast));
            diagnostics.set(doc.uri, diags);
        } catch {
            // Malformed JSON — ignore silently.
        }
    });

    // Send the document content and close stdin.
    proc.stdin.write(doc.getText());
    proc.stdin.end();
}

// ── helpers ───────────────────────────────────────────────────────────────────

function toDiagnostic(
    f: Finding,
    doc: vscode.TextDocument,
    noRoast: boolean
): vscode.Diagnostic {
    const line = Math.max(0, f.line - 1);
    const lineText = doc.lineAt(Math.min(line, doc.lineCount - 1));
    const range = new vscode.Range(
        line, lineText.firstNonWhitespaceCharacterIndex,
        line, lineText.range.end.character
    );

    const sev = f.severity === 'ERROR'
        ? vscode.DiagnosticSeverity.Error
        : f.severity === 'WARN'
            ? vscode.DiagnosticSeverity.Warning
            : vscode.DiagnosticSeverity.Information;

    // Include roast as a second line in the message so it shows in the
    // Problems panel and in the hover tooltip.
    const message = (!noRoast && f.roast)
        ? `${f.message}\n💬 ${f.roast}`
        : f.message;

    const diag = new vscode.Diagnostic(range, message, sev);
    diag.code = f.rule;
    diag.source = 'droast';
    return diag;
}

function isDockerfile(doc: vscode.TextDocument): boolean {
    if (doc.languageId === 'dockerfile') { return true; }
    const base = path.basename(doc.fileName);
    // Match Dockerfile, Dockerfile.dev, Dockerfile.prod, etc.
    return /^Dockerfile(\..+)?$/i.test(base);
}

/**
 * Resolve the droast executable path.
 * Priority: explicit config → bundled binary in extension/bin/ → system PATH.
 */
function resolveExecutable(configured: string): string {
    if (configured) { return configured; }

    const ext  = process.platform === 'win32' ? '.exe' : '';
    const arch = process.arch === 'arm64' ? 'arm64' : 'x86_64';
    const plat = process.platform === 'darwin' ? 'macos'
               : process.platform === 'win32'  ? 'windows'
               : 'linux';

    const bundled = path.join(__dirname, '..', 'bin', `droast-${plat}-${arch}${ext}`);
    if (fs.existsSync(bundled)) { return bundled; }

    return 'droast';   // fall back to system PATH
}

function clearTimer(key: string): void {
    const t = timers.get(key);
    if (t !== undefined) { clearTimeout(t); timers.delete(key); }
}

function killProc(key: string): void {
    procs.get(key)?.kill();
    procs.delete(key);
}
