package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// Opening other processes (lsass among them) for memory access is what
// credential theft looks like to endpoint security tools. The runner never
// asks for memory rights and never reads or writes another process's memory.
// This checks every OpenProcess call in the runner's sources on every OS.
func TestNoProcessIsOpenedForMemoryAccess(t *testing.T) {
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	constants := map[string]ast.Expr{}
	var files []*ast.File
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fileSet, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
		for _, declaration := range file.Decls {
			group, ok := declaration.(*ast.GenDecl)
			if !ok || group.Tok != token.CONST {
				continue
			}
			for _, spec := range group.Specs {
				value := spec.(*ast.ValueSpec)
				for index, constant := range value.Names {
					if index < len(value.Values) {
						constants[constant.Name] = value.Values[index]
					}
				}
			}
		}
	}
	forbidden := map[string]bool{
		"PROCESS_VM_READ":      true,
		"PROCESS_VM_WRITE":     true,
		"PROCESS_VM_OPERATION": true,
		"PROCESS_ALL_ACCESS":   true,
	}
	opens := 0
	for _, file := range files {
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := selector.X.(*ast.Ident); !ok || pkg.Name != "windows" {
				return true
			}
			position := fileSet.Position(call.Pos())
			switch selector.Sel.Name {
			case "ReadProcessMemory", "WriteProcessMemory":
				t.Errorf("%s: %s is not allowed", position, selector.Sel.Name)
			case "OpenProcess":
				opens++
				for _, right := range accessRights(t, call.Args[0], constants) {
					if forbidden[right] {
						t.Errorf("%s: OpenProcess asks for %s", position, right)
					}
				}
			}
			return true
		})
	}
	if opens == 0 {
		t.Fatal("no OpenProcess call was found, so nothing was checked")
	}
}

// accessRights lists the windows rights an access mask combines, following
// the runner's own named constants. Anything else, such as a numeric
// literal, cannot be checked and fails the test.
func accessRights(t *testing.T, mask ast.Expr, constants map[string]ast.Expr) []string {
	switch value := mask.(type) {
	case *ast.ParenExpr:
		return accessRights(t, value.X, constants)
	case *ast.BinaryExpr:
		if value.Op == token.OR {
			return append(accessRights(t, value.X, constants), accessRights(t, value.Y, constants)...)
		}
	case *ast.SelectorExpr:
		if pkg, ok := value.X.(*ast.Ident); ok && pkg.Name == "windows" {
			return []string{value.Sel.Name}
		}
	case *ast.Ident:
		if definition, ok := constants[value.Name]; ok {
			return accessRights(t, definition, constants)
		}
	}
	t.Errorf("an OpenProcess access mask cannot be checked; combine named windows rights with |")
	return nil
}
