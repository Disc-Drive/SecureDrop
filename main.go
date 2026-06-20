package main

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "html"
    "io"
    "io/fs"
    "net/http"
    "net/url"
    "os"
    "path/filepath"
    "sort"
    "strings"
    "time"

    "github.com/fsnotify/fsnotify"
    "gopkg.in/yaml.v3"
)

// ------ Config ------

var (
    inputDir      = "./input"
    quarantineDir = "./quarantine"
    outputDir     = "./output"
    exceptionDir  = "./exceptions"
    logFile       = "./audit.log"
    maxFileSize   = int64(10 * 1024 * 1024)
)

// ------ Rules Types ------

type Rule struct {
    Name     string   `yaml:"name"`
    Contains []string `yaml:"contains"`
    MoveTo   string   `yaml:"move_to"`
}

type RuleConfig struct {
    Rules []Rule `yaml:"rules"`
}

type ListedFile struct {
    Name       string
    Folder     string
    FullPath   string
    Size       int64
    ModifiedAt time.Time
}

var rules []Rule

// ------ Main ------

func main() {
    mustMkdir(inputDir)
    mustMkdir(quarantineDir)
    mustMkdir(outputDir)
    mustMkdir(exceptionDir)

    loadRules()

    watcher, err := fsnotify.NewWatcher()
    if err != nil {
        panic(err)
    }
    defer watcher.Close()

    if err := watcher.Add(inputDir); err != nil {
        panic(err)
    }

    go watchLoop(watcher)
    go startWebServer()

    fmt.Println("Watching:", inputDir)
    fmt.Println("Web UI: http://localhost:8080")

    select {}
}

// ------ Make Directory ------

func mustMkdir(path string) {
    if err := os.MkdirAll(path, 0755); err != nil {
        panic(err)
    }
}

// ------ Load Rules ------

func loadRules() {
    data, err := os.ReadFile("rules.yaml")
    if err != nil {
        fmt.Println("Failed to read rules.yaml:", err)
        rules = []Rule{}
        return
    }

    var config RuleConfig
    if err := yaml.Unmarshal(data, &config); err != nil {
        fmt.Println("Failed to parse rules.yaml:", err)
        rules = []Rule{}
        return
    }

    rules = config.Rules
}

// ------ Watch Loop ------

func watchLoop(watcher *fsnotify.Watcher) {
    for {
        select {
        case event := <-watcher.Events:
            if event.Op&fsnotify.Create == fsnotify.Create {
                go processFile(event.Name)
            }
        case err := <-watcher.Errors:
            if err != nil {
                fmt.Println("Watcher error:", err)
            }
        }
    }
}

// ------ Process File ------

func processFile(path string) {
    time.Sleep(500 * time.Millisecond)

    info, err := os.Stat(path)
    if err != nil {
        return
    }

    if info.IsDir() {
        return
    }

    filename := filepath.Base(path)
    qPath := filepath.Join(quarantineDir, filename)

    if err := os.Rename(path, qPath); err != nil {
        logAction(filename, "error", "failed to move to quarantine: "+err.Error())
        return
    }

    hash, size, err := validateFile(qPath)
    if err != nil {
        logAction(filename, "rejected", err.Error())
        return
    }

    content := extractText(qPath)
    category := classify(content, filename)

    var destDir string
    if category == "" {
        destDir = exceptionDir
        logAction(filename, "flagged", "no matching rule")
    } else {
        destDir = filepath.Join(outputDir, category)
    }

    if err := os.MkdirAll(destDir, 0755); err != nil {
        logAction(filename, "error", "failed to create destination directory: "+err.Error())
        return
    }

    newName := fmt.Sprintf("%d_%s", time.Now().Unix(), filename)
    destPath := filepath.Join(destDir, newName)

    if err := os.Rename(qPath, destPath); err != nil {
        logAction(filename, "error", "failed to move to final destination: "+err.Error())
        return
    }

    logAction(filename, "stored", fmt.Sprintf("dir=%s size=%d hash=%s", destDir, size, hash))
}

// ------ Validate File ------

func validateFile(path string) (string, int64, error) {
    file, err := os.Open(path)
    if err != nil {
        return "", 0, err
    }
    defer file.Close()

    info, err := file.Stat()
    if err != nil {
        return "", 0, err
    }

    if info.Size() > maxFileSize {
        return "", 0, fmt.Errorf("file too large")
    }

    hash := sha256.New()
    if _, err := io.Copy(hash, file); err != nil {
        return "", 0, err
    }

    return hex.EncodeToString(hash.Sum(nil)), info.Size(), nil
}

// ------ Extract Text ------

func extractText(path string) string {
    data, err := os.ReadFile(path)
    if err != nil {
        return ""
    }

    return strings.ToLower(string(data))
}

// ------ Classify ------

func classify(content string, name string) string {
    lowerContent := strings.ToLower(content)
    lowerName := strings.ToLower(name)

    for _, rule := range rules {
        for _, keyword := range rule.Contains {
            k := strings.ToLower(keyword)
            if strings.Contains(lowerContent, k) || strings.Contains(lowerName, k) {
                return rule.MoveTo
            }
        }
    }

    return ""
}

// ------ Logging ------

func logAction(file string, action string, details string) {
    entry := fmt.Sprintf(
        "%s | %s | %s | %s\n",
        time.Now().Format(time.RFC3339),
        file,
        action,
        details,
    )

    f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return
    }
    defer f.Close()

    _, _ = f.WriteString(entry)
}

// ------ Web Server ------

func startWebServer() {
    http.HandleFunc("/", dashboard)
    http.HandleFunc("/upload", upload)
    http.HandleFunc("/files", listFiles)
    http.HandleFunc("/logs", logs)
    http.HandleFunc("/open", openFile)
    http.HandleFunc("/download", download)

    if err := http.ListenAndServe(":8080", nil); err != nil {
        panic(err)
    }
}

// ------ Render Page ------

func renderPage(title string, active string, body string) string {
    return `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>` + html.EscapeString(title) + `</title>
    <style>
        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background-color: #0f172a;
            color: #e2e8f0;
        }
        .navbar {
            background: #020617;
            padding: 15px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .nav-title {
            color: #38bdf8;
            font-size: 20px;
            font-weight: bold;
        }
        .nav-links a {
            color: #60a5fa;
            margin-left: 20px;
            text-decoration: none;
        }
        .nav-links a.active {
            color: #ffffff;
            font-weight: bold;
        }
        .container {
            padding: 40px;
            max-width: 1100px;
            margin: 0 auto;
        }
        .card {
            background: #1e293b;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
        }
        #dropZone {
            border: 2px dashed #38bdf8;
            padding: 40px;
            text-align: center;
            border-radius: 8px;
            margin-bottom: 10px;
            cursor: pointer;
        }
        button {
            padding: 8px 16px;
            cursor: pointer;
            background: #38bdf8;
            border: none;
            border-radius: 6px;
            color: #0f172a;
            font-weight: bold;
        }
        input[type="file"] {
            display: none;
        }
        .file-table {
            width: 100%;
            border-collapse: collapse;
        }
        .file-table th,
        .file-table td {
            padding: 12px 10px;
            text-align: left;
            border-bottom: 1px solid #334155;
            vertical-align: top;
        }
        .file-table th {
            color: #cbd5e1;
            font-size: 14px;
        }
        .file-table td {
            color: #e2e8f0;
        }
        .muted {
            color: #94a3b8;
        }
        .empty {
            color: #94a3b8;
            padding: 8px 0;
        }
        .action-links a {
            display: inline-block;
            margin-right: 10px;
            padding: 6px 10px;
            border-radius: 6px;
            text-decoration: none;
            font-size: 14px;
        }
        .open-link {
            background: #334155;
            color: #e2e8f0;
        }
        .download-link {
            background: #38bdf8;
            color: #0f172a;
            font-weight: bold;
        }
        pre {
            white-space: pre-wrap;
            word-break: break-word;
        }
    </style>
</head>
<body>
` + navbarHTML(active) + `
    <div class="container">
` + body + `
    </div>
</body>
</html>`
}

// ------ Navbar HTML ------

func navbarHTML(active string) string {
    dashboardClass := ""
    filesClass := ""
    logsClass := ""

    if active == "dashboard" {
        dashboardClass = ` class="active"`
    }

    if active == "files" {
        filesClass = ` class="active"`
    }

    if active == "logs" {
        logsClass = ` class="active"`
    }

    return `
    <div class="navbar">
        <div class="nav-title">SecureDrop</div>
        <div class="nav-links">
            <a href="/"` + dashboardClass + `>Dashboard</a>
            <a href="/files"` + filesClass + `>Files</a>
            <a href="/logs"` + logsClass + `>Logs</a>
        </div>
    </div>`
}

// ------ Dashboard ------

func dashboard(w http.ResponseWriter, r *http.Request) {
    body := `
        <div class="card">
            <h2>Upload File</h2>
            <form action="/upload" method="post" enctype="multipart/form-data">
                <div id="dropZone">
                    Drag file here or click to upload
                    <input type="file" name="file" id="fileInput">
                </div>
                <button type="submit">Upload</button>
            </form>
        </div>

        <script>
            const dropZone = document.getElementById("dropZone");
            const fileInput = document.getElementById("fileInput");

            dropZone.addEventListener("click", function () {
                fileInput.click();
            });

            dropZone.addEventListener("dragover", function (e) {
                e.preventDefault();
                dropZone.style.background = "#1e40af";
            });

            dropZone.addEventListener("dragleave", function () {
                dropZone.style.background = "";
            });

            dropZone.addEventListener("drop", function (e) {
                e.preventDefault();

                if (e.dataTransfer.files.length > 0) {
                    fileInput.files = e.dataTransfer.files;
                }

                dropZone.style.background = "";
            });
        </script>
    `

    page := renderPage("SecureDrop", "dashboard", body)

    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    _, _ = w.Write([]byte(page))
}

// ------ Upload ------

func upload(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Redirect(w, r, "/", http.StatusSeeOther)
        return
    }

    if err := r.ParseMultipartForm(maxFileSize); err != nil {
        http.Error(w, "upload error", http.StatusBadRequest)
        return
    }

    file, header, err := r.FormFile("file")
    if err != nil {
        http.Error(w, "upload error", http.StatusBadRequest)
        return
    }
    defer file.Close()

    filename := filepath.Base(header.Filename)
    if filename == "" {
        http.Error(w, "missing filename", http.StatusBadRequest)
        return
    }

    dst, err := os.Create(filepath.Join(inputDir, filename))
    if err != nil {
        http.Error(w, "failed to save file", http.StatusInternalServerError)
        return
    }
    defer dst.Close()

    if _, err := io.Copy(dst, file); err != nil {
        http.Error(w, "failed to write file", http.StatusInternalServerError)
        return
    }

    http.Redirect(w, r, "/files", http.StatusSeeOther)
}

// ------ List Files ------

func listFiles(w http.ResponseWriter, r *http.Request) {
    outputFiles := collectFiles(outputDir)
    exceptionFiles := collectFiles(exceptionDir)

    var body strings.Builder

    body.WriteString(`<div class="card"><h2>Output</h2>`)
    body.WriteString(renderFileTable(outputFiles))
    body.WriteString(`</div>`)

    body.WriteString(`<div class="card"><h2>Exceptions</h2>`)
    body.WriteString(renderFileTable(exceptionFiles))
    body.WriteString(`</div>`)

    page := renderPage("SecureDrop Files", "files", body.String())

    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    _, _ = w.Write([]byte(page))
}

// ------ Collect Files ------

func collectFiles(root string) []ListedFile {
    files := []ListedFile{}

    filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
        if err != nil || d == nil || d.IsDir() {
            return nil
        }

        info, err := d.Info()
        if err != nil {
            return nil
        }

        relPath, err := filepath.Rel(root, path)
        if err != nil {
            relPath = d.Name()
        }

        folder := filepath.Dir(relPath)
        if folder == "." {
            folder = "/"
        }

        files = append(files, ListedFile{
            Name:       d.Name(),
            Folder:     filepath.ToSlash(folder),
            FullPath:   path,
            Size:       info.Size(),
            ModifiedAt: info.ModTime(),
        })

        return nil
    })

    sort.Slice(files, func(i int, j int) bool {
        return files[i].ModifiedAt.After(files[j].ModifiedAt)
    })

    return files
}

// ------ Render File Table ------

func renderFileTable(files []ListedFile) string {
    if len(files) == 0 {
        return `<div class="empty">No files yet.</div>`
    }

    var b strings.Builder

    b.WriteString(`
    <table class="file-table">
        <thead>
            <tr>
                <th>Name</th>
                <th>Folder</th>
                <th>Size</th>
                <th>Modified</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
    `)

    for _, file := range files {
        name := html.EscapeString(file.Name)
        folder := html.EscapeString(file.Folder)
        size := html.EscapeString(formatSize(file.Size))
        modified := html.EscapeString(file.ModifiedAt.Format("2006-01-02 3:04 PM"))
        openLink := "/open?path=" + url.QueryEscape(file.FullPath)
        downloadLink := "/download?path=" + url.QueryEscape(file.FullPath)

        b.WriteString(`
            <tr>
                <td>` + name + `</td>
                <td class="muted">` + folder + `</td>
                <td>` + size + `</td>
                <td>` + modified + `</td>
                <td>
                    <div class="action-links">
                        <a href="` + openLink + `" class="open-link">Open</a>
                        <a href="` + downloadLink + `" class="download-link">Download</a>
                    </div>
                </td>
            </tr>
        `)
    }

    b.WriteString(`
        </tbody>
    </table>
    `)

    return b.String()
}

// ------ Format Size ------

func formatSize(size int64) string {
    if size < 1024 {
        return fmt.Sprintf("%d B", size)
    }

    if size < 1024*1024 {
        return fmt.Sprintf("%.1f KB", float64(size)/1024)
    }

    if size < 1024*1024*1024 {
        return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
    }

    return fmt.Sprintf("%.1f GB", float64(size)/(1024*1024*1024))
}

// ------ Logs ------

func logs(w http.ResponseWriter, r *http.Request) {
    data, err := os.ReadFile(logFile)
    if err != nil {
        data = []byte("No logs yet")
    }

    body := `
        <div class="card">
            <h2>Logs</h2>
            <pre>` + html.EscapeString(string(data)) + `</pre>
        </div>
    `

    page := renderPage("SecureDrop Logs", "logs", body)

    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    _, _ = w.Write([]byte(page))
}

// ------ Resolve Allowed Path ------

func resolveAllowedPath(rawPath string) (string, error) {
    if rawPath == "" {
        return "", fmt.Errorf("missing path")
    }

    cleanPath := filepath.Clean(rawPath)
    absPath, err := filepath.Abs(cleanPath)
    if err != nil {
        return "", err
    }

    absOutput, err := filepath.Abs(outputDir)
    if err != nil {
        return "", err
    }

    absExceptions, err := filepath.Abs(exceptionDir)
    if err != nil {
        return "", err
    }

    if pathInside(absOutput, absPath) || pathInside(absExceptions, absPath) {
        return absPath, nil
    }

    return "", fmt.Errorf("path not allowed")
}

// ------ Path Inside ------

func pathInside(base string, target string) bool {
    rel, err := filepath.Rel(base, target)
    if err != nil {
        return false
    }

    if rel == "." {
        return true
    }

    if strings.HasPrefix(rel, "..") {
        return false
    }

    return true
}

// ------ Open File ------

func openFile(w http.ResponseWriter, r *http.Request) {
    rawPath := r.URL.Query().Get("path")

    path, err := resolveAllowedPath(rawPath)
    if err != nil {
        http.Error(w, "invalid path", http.StatusBadRequest)
        return
    }

    info, err := os.Stat(path)
    if err != nil || info.IsDir() {
        http.Error(w, "file not found", http.StatusNotFound)
        return
    }

    http.ServeFile(w, r, path)
}

// ------ Download ------

func download(w http.ResponseWriter, r *http.Request) {
    rawPath := r.URL.Query().Get("path")

    path, err := resolveAllowedPath(rawPath)
    if err != nil {
        http.Error(w, "invalid path", http.StatusBadRequest)
        return
    }

    info, err := os.Stat(path)
    if err != nil || info.IsDir() {
        http.Error(w, "file not found", http.StatusNotFound)
        return
    }

    safeName := strings.ReplaceAll(info.Name(), `"`, "")
    w.Header().Set("Content-Disposition", `attachment; filename="`+safeName+`"`)
    http.ServeFile(w, r, path)
}