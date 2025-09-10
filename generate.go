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
	"strings"
	"text/template"
)

const (
	theoryTmpl = `theory {{.theoryName}}
begin
{{range .rules}}
rule {{makeRuleName .ruleName}} [trigger=[<{{.funcName}}({{.args}}), <{{.results}}>>]]:
  [ ] --[ ]-> [ ]
{{end}}
end`
)

func GenerateTheory(rules []map[string]string) string {
	funcMap := template.FuncMap{
		"makeRuleName": convertFuncName,
	}

	template := template.Must(template.New("theory").Funcs(funcMap).Parse(theoryTmpl))

	t := map[string]interface{}{
		"theoryName": "Preprocess",
		"rules":      rules,
	}

	var buf bytes.Buffer
	if err := template.Execute(&buf, t); err != nil {
		return ""
	}
	return buf.String()
}

func convertFuncName(funcName string) string {
	parts := strings.Split(funcName, ".")
	for i, part := range parts {
		if len(part) > 0 {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
	}
	return strings.Join(parts, "")
}
