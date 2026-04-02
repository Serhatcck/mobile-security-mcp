# mobile-mcp-security demo
# Generate with: brew install charmbracelet/tap/vhs && vhs docs/demo.tape

Output docs/demo.gif

Set Shell zsh
Set FontSize 14
Set Width 1200
Set Height 600
Set Theme "Dracula"

# Build first
Type "npm run build"
Enter
Sleep 2s

# Run manifest analyzer
Type `node -e "import('./dist/tools/android/manifest-analyzer.js').then(m => m.apkManifestAnalyzer.handler({apk_path:'./example.apk'})).then(r => console.log(r.content[0].text))"`
Enter
Sleep 5s

# Run permissions checker
Type `node -e "import('./dist/tools/android/permissions-checker.js').then(m => m.apkPermissionsChecker.handler({apk_path:'./example.apk'})).then(r => console.log(r.content[0].text))"`
Enter
Sleep 5s

# Run secrets scanner
Type `node -e "import('./dist/tools/android/secrets-scanner.js').then(m => m.androidSecretsScanner.handler({apk_path:'./example.apk'})).then(r => console.log(r.content[0].text))"`
Enter
Sleep 5s
