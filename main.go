package main

import (
	"crypto/rand"
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
	"sync"
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
	maxPathLength = 1024
	maxRuleSize   = 10 * 1024 * 1024
	workerCount   = 4
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

var (
	rules      []Rule
	rulesMutex sync.RWMutex
	csrfTokens = make(map[string]time.Time)
	csrfMutex  sync.Mutex
)

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

	// Worker pool for file processing
	fileQueue := make(chan string, 100)
	for i := 0; i < workerCount; i++ {
		go fileWorker(fileQueue)
	}

	go watchLoop(watcher, fileQueue)
	go startWebServer()

	fmt.Println("Watching:", inputDir)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Web UI: http://localhost:%s\n", port)

	select {}
}

// ------ File Worker ------

func fileWorker(queue chan string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Worker panic: %v\n", r)
		}
	}()

	for path := range queue {
		processFile(path)
	}
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
		rulesMutex.Lock()
		rules = []Rule{}
		rulesMutex.Unlock()
		return
	}

	if len(data) > maxRuleSize {
		fmt.Println("rules.yaml too large")
		rulesMutex.Lock()
		rules = []Rule{}
		rulesMutex.Unlock()
		return
	}

	var config RuleConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		fmt.Println("Failed to parse rules.yaml:", err)
		rulesMutex.Lock()
		rules = []Rule{}
		rulesMutex.Unlock()
		return
	}

	rulesMutex.Lock()
	rules = config.Rules
	rulesMutex.Unlock()
}

// ------ Watch Loop ------

func watchLoop(watcher *fsnotify.Watcher, queue chan string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Watcher panic: %v\n", r)
		}
	}()

	for {
		select {
		case event := <-watcher.Events:
			if event.Op&fsnotify.Create == fsnotify.Create {
				queue <- event.Name
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

	// Atomic file move using rename
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

	rulesMutex.RLock()
	defer rulesMutex.RUnlock()

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

// ------ CSRF Token Management ------

func generateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	token := hex.EncodeToString(b)

	csrfMutex.Lock()
	csrfTokens[token] = time.Now().Add(1 * time.Hour)
	csrfMutex.Unlock()

	return token
}

func validateCSRFToken(token string) bool {
	if token == "" {
		return false
	}

	csrfMutex.Lock()
	defer csrfMutex.Unlock()

	expiry, exists := csrfTokens[token]
	if !exists || time.Now().After(expiry) {
		return false
	}

	delete(csrfTokens, token)
	return true
}

// ------ Get Unique Categories ------

func getUniqueCategories() []string {
	categorySet := make(map[string]bool)

	rulesMutex.RLock()
	defer rulesMutex.RUnlock()

	for _, rule := range rules {
		if rule.MoveTo != "" {
			categorySet[rule.MoveTo] = true
		}
	}

	categories := make([]string, 0, len(categorySet))
	for cat := range categorySet {
		categories = append(categories, cat)
	}

	sort.Strings(categories)
	return categories
}

// ------ Web Server ------

func startWebServer() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Web server panic: %v\n", r)
		}
	}()

	http.HandleFunc("/", dashboard)
	http.HandleFunc("/upload", upload)
	http.HandleFunc("/files", listFiles)
	http.HandleFunc("/logs", logs)
	http.HandleFunc("/open", openFile)
	http.HandleFunc("/download", download)
	http.HandleFunc("/moveException", moveException)
	http.HandleFunc("/ignoreException", ignoreException)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Printf("Web server error: %v\n", err)
	}
}

// ------ Render Page ------

func renderPage(title string, active string, body string, csrfToken string) string {
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
        .action-buttons {
            display: flex;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap;
        }
        .action-buttons select {
            padding: 6px 10px;
            font-size: 14px;
            background: #334155;
            color: #e2e8f0;
            border: 1px solid #475569;
            border-radius: 6px;
            cursor: pointer;
        }
        .action-buttons button {
            padding: 6px 10px;
            font-size: 14px;
        }
        .move-btn {
            background: #10b981;
            color: #ffffff;
        }
        .ignore-btn {
            background: #6366f1;
            color: #ffffff;
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
	csrfToken := generateCSRFToken()

	body := `
        <div class="card">
            <h2>Upload File</h2>
            <form action="/upload" method="post" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="` + html.EscapeString(csrfToken) + `">
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

	page := renderPage("SecureDrop", "dashboard", body, csrfToken)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page))
}

// ------ Upload ------

func upload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// CSRF validation
	if err := r.ParseMultipartForm(maxFileSize); err != nil {
		http.Error(w, "upload error", http.StatusBadRequest)
		return
	}

	csrfToken := r.FormValue("csrf_token")
	if !validateCSRFToken(csrfToken) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "upload error", http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename := filepath.Base(header.Filename)
	if filename == "" || filename == "." || filename == ".." {
		http.Error(w, "invalid filename", http.StatusBadRequest)
		return
	}

	// Sanitize filename
	filename = strings.ReplaceAll(filename, "/", "_")
	filename = strings.ReplaceAll(filename, "\\", "_")

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
	body.WriteString(renderExceptionTable(exceptionFiles))
	body.WriteString(`</div>`)

	page := renderPage("SecureDrop Files", "files", body.String(), "")

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

// ------ Render Exception Table ------

func renderExceptionTable(files []ListedFile) string {
	if len(files) == 0 {
		return `<div class="empty">No exceptions yet.</div>`
	}

	categories := getUniqueCategories()
	var categoryOptions strings.Builder

	categoryOptions.WriteString(`<option value="">-- Select Category --</option>`)
	for _, cat := range categories {
		categoryOptions.WriteString(`<option value="` + html.EscapeString(cat) + `">` + html.EscapeString(cat) + `</option>`)
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

		b.WriteString(`
            <tr>
                <td>` + name + `</td>
                <td class="muted">` + folder + `</td>
                <td>` + size + `</td>
                <td>` + modified + `</td>
                <td>
                    <div class="action-buttons">
                        <form action="/moveException" method="post" style="display:inline-flex; gap:5px; align-items:center;">
                            <input type="hidden" name="path" value="` + url.QueryEscape(file.FullPath) + `">
                            <select name="category" required>
                                ` + categoryOptions.String() + `
                            </select>
                            <button type="submit" class="move-btn">Move</button>
                        </form>
                        <form action="/ignoreException" method="post" style="display:inline;">
                            <input type="hidden" name="path" value="` + url.QueryEscape(file.FullPath) + `">
                            <button type="submit" class="ignore-btn">Ignore</button>
                        </form>
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

	page := renderPage("SecureDrop Logs", "logs", body, "")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page))
}

// ------ Resolve Allowed Path ------

func resolveAllowedPath(rawPath string) (string, error) {
	if rawPath == "" {
		return "", fmt.Errorf("missing path")
	}

	if len(rawPath) > maxPathLength {
		return "", fmt.Errorf("path too long")
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

	// Fix path traversal: use only basename
	safeName := filepath.Base(info.Name())
	safeName = strings.ReplaceAll(safeName, `"`, "")
	w.Header().Set("Content-Disposition", `attachment; filename="`+safeName+`"`)
	http.ServeFile(w, r, path)
}

// ------ Move Exception ------

func moveException(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	rawPath := r.FormValue("path")
	category := r.FormValue("category")

	if rawPath == "" || category == "" {
		http.Error(w, "missing path or category", http.StatusBadRequest)
		return
	}

	path, err := resolveAllowedPath(rawPath)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	// Verify the file is in the exceptions directory
	absExceptions, err := filepath.Abs(exceptionDir)
	if err != nil || !pathInside(absExceptions, path) {
		http.Error(w, "file not in exceptions", http.StatusBadRequest)
		return
	}

	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}

	// Create destination directory
	destDir := filepath.Join(outputDir, category)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		http.Error(w, "failed to create destination", http.StatusInternalServerError)
		return
	}

	// Move file with timestamped name
	newName := fmt.Sprintf("%d_%s", time.Now().Unix(), info.Name())
	destPath := filepath.Join(destDir, newName)

	if err := os.Rename(path, destPath); err != nil {
		http.Error(w, "failed to move file", http.StatusInternalServerError)
		return
	}

	logAction(info.Name(), "moved", fmt.Sprintf("from=exceptions to=%s", category))
	http.Redirect(w, r, "/files", http.StatusSeeOther)
}

// ------ Ignore Exception ------

func ignoreException(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	rawPath := r.FormValue("path")

	if rawPath == "" {
		http.Error(w, "missing path", http.StatusBadRequest)
		return
	}

	path, err := resolveAllowedPath(rawPath)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	// Verify the file is in the exceptions directory
	absExceptions, err := filepath.Abs(exceptionDir)
	if err != nil || !pathInside(absExceptions, path) {
		http.Error(w, "file not in exceptions", http.StatusBadRequest)
		return
	}

	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}

	logAction(info.Name(), "ignored", "remains in exceptions")
	http.Redirect(w, r, "/files", http.StatusSeeOther)
}
