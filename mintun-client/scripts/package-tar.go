// Creates desktop tarballs with correct Unix modes even on a Windows build host.
package main

import (
    "archive/tar"
    "compress/gzip"
    "errors"
    "fmt"
    "io"
    "io/fs"
    "os"
    "path/filepath"
    "strings"
    "time"
)

func main() {
    if len(os.Args) != 3 { fmt.Fprintln(os.Stderr, "usage: package-tar <package-directory> <output.tar.gz>"); os.Exit(2) }
    if err := pack(os.Args[1], os.Args[2]); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}

func pack(root, output string) (result error) {
    root, err := filepath.Abs(root)
    if err != nil { return err }
    output, err = filepath.Abs(output)
    if err != nil { return err }
    if relative, err := filepath.Rel(root, output); err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) { return errors.New("output must be outside the package directory") }
    file, err := os.CreateTemp(filepath.Dir(output), ".mintun-package-*.tmp")
    if err != nil { return err }
    temporary := file.Name()
    defer func() { file.Close(); if result != nil { os.Remove(temporary) } }()
    zipped := gzip.NewWriter(file)
    writer := tar.NewWriter(zipped)
    err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkError error) error {
        if walkError != nil { return walkError }
        if path == root { return nil }
        relative, err := filepath.Rel(root, path)
        if err != nil { return err }
        name := filepath.ToSlash(relative)
        info, err := entry.Info()
        if err != nil { return err }
        if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) { return fmt.Errorf("non-regular package entry: %s", name) }
        mode := int64(0644)
        if info.IsDir() || filepath.Base(name) == "MinTunClient" || filepath.Base(name) == "sing-box" { mode = 0755 }
        header := &tar.Header{Name:name,Mode:mode,ModTime:time.Unix(0,0),Format:tar.FormatUSTAR}
        if info.IsDir() { header.Typeflag=tar.TypeDir; header.Name+="/" } else { header.Typeflag=tar.TypeReg; header.Size=info.Size() }
        if err := writer.WriteHeader(header); err != nil { return err }
        if !info.IsDir() {
            source, err := os.Open(path)
            if err != nil { return err }
            _, copyError := io.Copy(writer, source)
            closeError := source.Close()
            if copyError != nil { return copyError }
            if closeError != nil { return closeError }
        }
        return nil
    })
    if err != nil { return err }
    if err = writer.Close(); err != nil { return err }
    if err = zipped.Close(); err != nil { return err }
    if err = file.Sync(); err != nil { return err }
    if err = file.Close(); err != nil { return err }
    return os.Rename(temporary,output)
}
