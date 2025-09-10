// Copyright (C) 2025 CISPA Helmholtz Center for Information Security
// Author: Kevin Morio <kevin.morio@cispa.de>
//
// This file is part of go-annotate.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the MIT License as published by
// the Open Source Initiative.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// MIT License for more details.
//
// You should have received a copy of the MIT License
// along with this program. If not, see <https://opensource.org/licenses/MIT>.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"log"
	"os"
	"strings"
	"text/template"

	"golang.org/x/tools/go/ast/astutil"
)

const (
	importName   = "__log"
	resultPrefix = "res"
	separator    = "_"

	enterTmpl = `
__traceID := __log.ID()
__log.LogEnter(__traceID, "{{.fname}}", []any{{"{"}}{{.args}}{{"}"}})`

	leaveTmpl = `
defer func() {
	__log.LogLeave(__traceID, "{{.fname}}", []any{{"{"}}{{.args}}{{"}"}}, []any{{"{"}}{{.results}}{{"}"}})
}()`
)

// Config holds all configuration options for the annotator.
type Config struct {
	ShowReturn   bool
	ExportedOnly bool
	Prefix       string
	ShowPackage  bool
	WriteFiles   bool
	FormatLength int
	Timing       bool
	ImportPath   string
	GeneratePath string
}

// Annotator encapsulates the code annotation functionality.
type Annotator struct {
	config        *Config
	fset          *token.FileSet
	enterTemplate *template.Template
	leaveTemplate *template.Template
	rules         []map[string]string
}

// FunctionInfo holds extracted information about a function.
type FunctionInfo struct {
	Name           string
	ReceiverNames  []string
	ArgNames       []string
	RetNames       []string
	HasNamedReturn bool
}

// NewAnnotator creates a new annotator instance with the given configuration.
func NewAnnotator(config *Config) (*Annotator, error) {
	enterTemplate, err := template.New("enter").Parse(enterTmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse enter template: %w", err)
	}

	leaveTemplate, err := template.New("leave").Parse(leaveTmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leave template: %w", err)
	}

	return &Annotator{
		config:        config,
		fset:          token.NewFileSet(),
		enterTemplate: enterTemplate,
		leaveTemplate: leaveTemplate,
		rules:         make([]map[string]string, 0),
	}, nil
}

// debugCall generates enter and leave statement strings for function instrumentation.
func (a *Annotator) debugCall(fName string, pos token.Pos, args []string, results []string, packageName string) (string, string) {
	vals := make(map[string]string)

	vals["args"] = ""
	if len(args) > 0 {
		vals["args"] = strings.Join(args, ", ")
	}

	vals["results"] = ""
	if len(results) > 0 {
		vals["results"] = strings.Join(results, ", ")
	}

	if a.config.Timing {
		vals["timing"] = "true"
	}

	vals["fname"] = fName
	if a.config.ShowPackage {
		vals["fname"] = packageName + separator + fName
	}

	if pos.IsValid() {
		vals["position"] = a.fset.Position(pos).String()
	}

	if a.config.ShowReturn {
		vals["return"] = "true"
	}

	var enter, leave bytes.Buffer
	if err := a.enterTemplate.Execute(&enter, vals); err != nil {
		log.Fatalf("Failed to execute enter template: %v", err)
	}

	if err := a.leaveTemplate.Execute(&leave, vals); err != nil {
		log.Fatalf("Failed to execute leave template: %v", err)
	}

	return enter.String(), leave.String()
}

// AnnotateFile reads, annotates, and optionally writes back a Go source file.
func (a *Annotator) AnnotateFile(file string) error {
	orig, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", file, err)
	}

	src, err := a.AnnotateSource(file, orig)
	if err != nil {
		return fmt.Errorf("failed to annotate file %s: %w", file, err)
	}

	if !a.config.WriteFiles {
		fmt.Println(string(src))
		return nil
	}

	if err := os.WriteFile(file, src, 0); err != nil {
		return fmt.Errorf("failed to write file %s: %w", file, err)
	}

	return nil
}

// AnnotateSource parses Go source code and annotates functions with instrumentation.
func (a *Annotator) AnnotateSource(filename string, orig []byte) ([]byte, error) {
	orig, err := format.Source(orig)
	if err != nil {
		return orig, err
	}

	f, err := parser.ParseFile(a.fset, filename, orig, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	packageName := f.Name.Name
	requiresImport := false

	astutil.Apply(f, nil, func(c *astutil.Cursor) bool {
		if decl, ok := c.Node().(*ast.FuncDecl); ok {
			if a.config.ExportedOnly && !ast.IsExported(decl.Name.Name) {
				return true
			}

			if annotatedFunc, rule, annotated := a.annotateFunction(decl, packageName); annotated {
				c.Replace(annotatedFunc)
				requiresImport = true

				rule["ruleName"] = packageName + separator + rule["ruleName"]
				rule["funcName"] = packageName + separator + rule["funcName"]
				a.rules = append(a.rules, rule)
			}
		}
		return true
	})

	if requiresImport {
		astutil.AddNamedImport(a.fset, f, importName, a.config.ImportPath)
	}

	var buf bytes.Buffer
	if err := format.Node(&buf, a.fset, f); err != nil {
		return nil, fmt.Errorf("format.Node: %w", err)
	}

	return buf.Bytes(), nil
}

// extractFunctionInfo extracts metadata from a function declaration.
func (a *Annotator) extractFunctionInfo(target *ast.FuncDecl) *FunctionInfo {
	info := &FunctionInfo{
		Name: funcName(target),
	}

	// If the function is a method, add the receiver to the argument list.
	if target.Recv != nil {
		for _, param := range target.Recv.List {
			for _, name := range param.Names {
				info.ReceiverNames = append(info.ReceiverNames, name.Name)
			}
		}
	}

	info.ArgNames = paramNames(target.Type.Params)
	info.RetNames = resultNames(target.Type.Results)

	info.HasNamedReturn = true
	if len(info.RetNames) > 0 && strings.HasPrefix(info.RetNames[0], resultPrefix) {
		info.HasNamedReturn = false
	}

	return info
}

// createFunctionCall creates an AST call expression that invokes the original function as a closure.
func (a *Annotator) createFunctionCall(target *ast.FuncDecl) *ast.CallExpr {
	funcDecl := &ast.FuncLit{
		Type: &ast.FuncType{
			Results: target.Type.Results,
		},
		Body: target.Body,
	}

	return &ast.CallExpr{
		Fun: funcDecl,
	}
}

// createAssignment creates an AST assignment statement for function call results.
func (a *Annotator) createAssignment(info *FunctionInfo, funcCall *ast.CallExpr) *ast.AssignStmt {
	tokType := token.DEFINE
	if info.HasNamedReturn {
		tokType = token.ASSIGN
	}

	funcAssign := &ast.AssignStmt{
		Lhs: []ast.Expr{},
		Tok: tokType,
		Rhs: []ast.Expr{funcCall},
	}

	for _, ret := range info.RetNames {
		funcAssign.Lhs = append(funcAssign.Lhs, ast.NewIdent(ret))
	}

	return funcAssign
}

// createReturnStatement creates an AST return statement for functions with unnamed return values.
func (a *Annotator) createReturnStatement(info *FunctionInfo) *ast.ReturnStmt {
	funcRet := &ast.ReturnStmt{
		Results: []ast.Expr{},
	}

	if !info.HasNamedReturn {
		for _, ret := range info.RetNames {
			funcRet.Results = append(funcRet.Results, ast.NewIdent(ret))
		}
	}

	return funcRet
}

// annotateFunction transforms a function declaration by adding instrumentation logging.
func (a *Annotator) annotateFunction(target *ast.FuncDecl, packageName string) (*ast.FuncDecl, map[string]string, bool) {
	if target.Body == nil {
		return target, nil, false
	}

	info := a.extractFunctionInfo(target)
	funcCall := a.createFunctionCall(target)
	funcAssign := a.createAssignment(info, funcCall)

	rule := map[string]string{
		"ruleName": info.Name,
		"funcName": info.Name,
		"args":     strings.Join(append(info.ReceiverNames, info.ArgNames...), ", "),
		"results":  strings.Join(info.RetNames, ", "),
	}

	enterStr, leaveStr := a.debugCall(info.Name, target.Pos(), append(info.ReceiverNames, info.ArgNames...), info.RetNames, packageName)

	enterStmt, err := a.parseStmts(enterStr)
	if err != nil {
		log.Fatalf("Failed to parse enter statement: %v", err)
	}

	leaveStmt, err := a.parseStmts(leaveStr)
	if err != nil {
		log.Fatalf("Failed to parse leave statement: %v", err)
	}

	funcRet := a.createReturnStatement(info)

	var bodyList []ast.Stmt
	if len(info.RetNames) > 0 {
		bodyList = append(bodyList, enterStmt...)
		bodyList = append(bodyList, funcAssign)
		bodyList = append(bodyList, leaveStmt...)
		bodyList = append(bodyList, funcRet)
	} else {
		bodyList = append(bodyList, enterStmt...)
		bodyList = append(bodyList, leaveStmt...)
		bodyList = append(bodyList, target.Body.List...)
	}

	annotatedFuncDecl := &ast.FuncDecl{
		Recv: target.Recv,
		Name: target.Name,
		Type: &ast.FuncType{
			Params:  target.Type.Params,
			Results: target.Type.Results,
		},
		Body: &ast.BlockStmt{
			List: bodyList,
		},
	}

	return annotatedFuncDecl, rule, true
}

// paramNames converts function parameters to a list of names.
func paramNames(params *ast.FieldList) []string {
	var p []string
	if (params == nil) || (params.List == nil) {
		return p
	}

	for _, f := range params.List {
		for _, n := range f.Names {
			p = append(p, n.Name)
		}
	}
	return p
}

// resultNames converts function parameters to a list of names.
func resultNames(results *ast.FieldList) []string {
	var p []string
	if (results == nil) || (results.List == nil) {
		return p
	}

	for _, f := range results.List {
		if f.Names != nil {
			for _, n := range f.Names {
				p = append(p, n.Name)
			}
		} else {
			p = append(p, fmt.Sprintf("%s%d", resultPrefix, len(p)+1))
		}
	}

	return p
}

// parseStmts parses a Go statement string into AST statement nodes.
func (a *Annotator) parseStmts(s string) ([]ast.Stmt, error) {
	// Parse the source code string in a minimal Go file structure
	src := "package main; func _() { " + s + " }"

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, 0)
	if err != nil {
		return nil, err
	}

	stmts := f.Decls[0].(*ast.FuncDecl).Body.List
	return stmts, nil
}

// funcName extracts the qualified name of a function, including receiver type for methods.
func funcName(f *ast.FuncDecl) string {
	if f.Recv != nil && len(f.Recv.List) > 0 {
		switch t := f.Recv.List[0].Type.(type) {
		case *ast.StarExpr:
			name, ok := t.X.(*ast.Ident)
			if ok {
				return name.Name + separator + f.Name.Name
			}
			return ""
		case *ast.Ident:
			return t.Name + separator + f.Name.Name
		}
	}

	return f.Name.Name
}

// WriteTheory writes monitoring rules to the specified output file.
func (a *Annotator) WriteTheory(outputPath string) error {
	file, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY, 0o666)
	if err != nil {
		return fmt.Errorf("failed to open theory file: %w", err)
	}
	defer file.Close()

	_, err = file.WriteString(GenerateTheory(a.rules))
	if err != nil {
		return fmt.Errorf("failed to write theory: %w", err)
	}

	return nil
}

// main processes command line arguments and orchestrates the code annotation workflow.
func main() {
	var config Config
	flag.BoolVar(&config.ShowReturn, "returns", false, "show function return")
	flag.BoolVar(&config.ExportedOnly, "exported", false, "only annotate exported functions")
	flag.StringVar(&config.Prefix, "prefix", "", "log prefix")
	flag.BoolVar(&config.ShowPackage, "package", false, "show package name prefix on function calls")
	flag.BoolVar(&config.WriteFiles, "w", false, "re-write files in place")
	flag.IntVar(&config.FormatLength, "formatLength", 1024, "limit the formatted length of each argument to 'size'")
	flag.BoolVar(&config.Timing, "timing", false, "print function durations. Implies -returns")
	flag.StringVar(&config.ImportPath, "import", "", "import path for the log package")
	flag.StringVar(&config.GeneratePath, "generate", "", "rule path for monitoring rules")
	flag.Parse()

	if flag.NArg() < 1 {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if config.Timing {
		config.ShowReturn = true
	}

	annotator, err := NewAnnotator(&config)
	if err != nil {
		log.Fatalf("Failed to create annotator: %v", err)
	}

	for _, file := range flag.Args() {
		if err := annotator.AnnotateFile(file); err != nil {
			log.Printf("Error processing file %s: %v", file, err)
		}
	}

	if config.GeneratePath != "" {
		if err := annotator.WriteTheory(config.GeneratePath); err != nil {
			log.Fatalf("Failed to write theory: %v", err)
		}
	}
}
