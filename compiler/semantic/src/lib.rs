//! TraceForge Semantic Analysis - Type checking and validation

use std::collections::HashSet;
use thiserror::Error;
use traceforge_ast::{
    Capability, CollectOptions, CollectTarget, Diagnostic, ExportFormat, Expr, HashAlgorithm,
    Investigation, Span, Stmt,
};
use traceforge_ir::{
    IrCollectOperation, IrExportOperation, IrFilterOperation, IrInvestigation, IrLimitOperation,
    IrMetadataOperation, IrOperation, IrWhereOperation,
};

#[derive(Debug, Error)]
pub enum SemanticError {
    #[error("Validation error: {0}")]
    ValidationError(String),
}

pub struct SemanticAnalyzer {
    diagnostics: Vec<Diagnostic>,
    required_capabilities: HashSet<Capability>,
}

impl SemanticAnalyzer {
    pub fn new() -> Self {
        Self {
            diagnostics: Vec::new(),
            required_capabilities: HashSet::new(),
        }
    }

    pub fn analyze(
        &mut self,
        investigation: &Investigation,
    ) -> Result<IrInvestigation, Vec<Diagnostic>> {
        self.diagnostics.clear();
        self.required_capabilities.clear();

        // Validate investigation structure
        self.validate_investigation(investigation)?;

        // Convert to IR
        let ir = self.convert_to_ir(investigation)?;

        if !self.diagnostics.is_empty() {
            let diags = std::mem::take(&mut self.diagnostics);
            return Err(diags);
        }

        Ok(ir)
    }

    pub fn analyze_with_diagnostics(
        &mut self,
        investigation: &Investigation,
    ) -> (Option<IrInvestigation>, Vec<Diagnostic>) {
        let result = self.analyze(investigation);
        let diags = std::mem::take(&mut self.diagnostics);

        match result {
            Ok(ir) => (Some(ir), diags),
            Err(mut e) => {
                e.extend(diags);
                (None, e)
            }
        }
    }

    pub fn required_capabilities(&self) -> &HashSet<Capability> {
        &self.required_capabilities
    }

    fn validate_investigation(
        &mut self,
        investigation: &Investigation,
    ) -> Result<(), Vec<Diagnostic>> {
        // Check for duplicate statement types that shouldn't be duplicated
        let mut has_export = false;
        let mut has_metadata = false;

        for stmt in &investigation.statements {
            match stmt {
                Stmt::Export { .. } => {
                    if has_export {
                        self.add_error("Multiple export statements not allowed", stmt.span());
                    }
                    has_export = true;
                }
                Stmt::Metadata(_, _) => {
                    if has_metadata {
                        self.add_error("Multiple metadata statements not allowed", stmt.span());
                    }
                    has_metadata = true;
                }
                _ => {}
            }
        }

        // Must have at least one collect statement
        let has_collect = investigation
            .statements
            .iter()
            .any(|s| matches!(s, Stmt::Collect { .. }));
        if !has_collect {
            self.add_error(
                "Investigation must have at least one 'collect' statement",
                investigation.span,
            );
        }

        // Must have export statement
        if !has_export {
            self.add_error(
                "Investigation must have an 'export evidence' statement",
                investigation.span,
            );
        }

        Ok(())
    }

    fn convert_to_ir(
        &mut self,
        investigation: &Investigation,
    ) -> Result<IrInvestigation, Vec<Diagnostic>> {
        let mut operations = Vec::new();

        for stmt in &investigation.statements {
            match stmt {
                Stmt::Collect {
                    target,
                    options,
                    span,
                } => {
                    let ops = self.convert_collect(target, options, *span)?;
                    operations.extend(ops);
                }
                Stmt::Export { format, path, span } => {
                    operations.push(IrOperation::Export(IrExportOperation {
                        format: self.convert_export_format(*format),
                        path: path.clone(),
                        span: *span,
                    }));
                }
                Stmt::Filter { condition, span } => {
                    operations.push(IrOperation::Filter(IrFilterOperation {
                        condition: self.convert_expression(condition)?,
                        span: *span,
                    }));
                }
                Stmt::Where { condition, span } => {
                    operations.push(IrOperation::Where(IrWhereOperation {
                        condition: self.convert_expression(condition)?,
                        span: *span,
                    }));
                }
                Stmt::Limit { count, span } => {
                    operations.push(IrOperation::Limit(IrLimitOperation {
                        count: self.convert_expression(count)?,
                        span: *span,
                    }));
                }
                Stmt::Metadata(metadata, span) => {
                    let mut ir_metadata = Vec::new();
                    for (key, value) in metadata {
                        ir_metadata.push((key.clone(), self.convert_expression(value)?));
                    }
                    operations.push(IrOperation::Metadata(IrMetadataOperation {
                        metadata: ir_metadata,
                        span: *span,
                    }));
                }
            }
        }

        // Convert metadata
        let mut ir_metadata = Vec::new();
        for (key, value) in &investigation.metadata {
            ir_metadata.push((key.clone(), self.convert_expression(value)?));
        }

        Ok(IrInvestigation {
            name: investigation.name.clone(),
            metadata: ir_metadata,
            operations,
            required_capabilities: self.required_capabilities.clone(),
            span: investigation.span,
        })
    }

    fn convert_collect(
        &mut self,
        target: &CollectTarget,
        options: &CollectOptions,
        span: Span,
    ) -> Result<Vec<IrOperation>, Vec<Diagnostic>> {
        match target {
            CollectTarget::SystemInfo => {
                self.required_capabilities
                    .insert(Capability::SystemInfoRead);
                Ok(vec![IrOperation::Collect(IrCollectOperation {
                    operation: "system.info".to_string(),
                    fields: vec![],
                    options: self.convert_collect_options(options)?,
                    span,
                })])
            }
            CollectTarget::Processes => {
                self.required_capabilities.insert(Capability::ProcessRead);
                if options.hash_algorithm.is_some() {
                    self.required_capabilities.insert(Capability::FileHash);
                }
                Ok(vec![IrOperation::Collect(IrCollectOperation {
                    operation: "process.enumerate".to_string(),
                    fields: options.fields.clone(),
                    options: self.convert_collect_options(options)?,
                    span,
                })])
            }
            CollectTarget::NetworkConnections => {
                self.required_capabilities.insert(Capability::NetworkRead);
                Ok(vec![IrOperation::Collect(IrCollectOperation {
                    operation: "network.connections".to_string(),
                    fields: vec![],
                    options: self.convert_collect_options(options)?,
                    span,
                })])
            }
            CollectTarget::Files { path } => {
                self.required_capabilities
                    .insert(Capability::FilesystemRead);
                if options.hash_algorithm.is_some() {
                    self.required_capabilities.insert(Capability::FileHash);
                }
                let mut opts = self.convert_collect_options(options)?;
                opts.insert("path".to_string(), serde_json::Value::String(path.clone()));
                Ok(vec![IrOperation::Collect(IrCollectOperation {
                    operation: "filesystem.enumerate".to_string(),
                    fields: vec![],
                    options: opts,
                    span,
                })])
            }
            CollectTarget::Logs { source } => {
                self.required_capabilities.insert(Capability::LogRead);
                let mut opts = self.convert_collect_options(options)?;
                opts.insert(
                    "source".to_string(),
                    serde_json::Value::String(source.clone()),
                );
                Ok(vec![IrOperation::Collect(IrCollectOperation {
                    operation: "logs.collect".to_string(),
                    fields: vec![],
                    options: opts,
                    span,
                })])
            }
            CollectTarget::Evidence { format } => {
                let mut opts = self.convert_collect_options(options)?;
                opts.insert(
                    "format".to_string(),
                    serde_json::Value::String(format.clone()),
                );
                Ok(vec![IrOperation::Collect(IrCollectOperation {
                    operation: "evidence.export".to_string(),
                    fields: vec![],
                    options: opts,
                    span,
                })])
            }
        }
    }

    fn convert_collect_options(
        &self,
        options: &CollectOptions,
    ) -> Result<serde_json::Map<String, serde_json::Value>, Vec<Diagnostic>> {
        let mut map = serde_json::Map::new();

        if !options.fields.is_empty() {
            map.insert(
                "fields".to_string(),
                serde_json::Value::Array(
                    options
                        .fields
                        .iter()
                        .map(|f| serde_json::Value::String(f.clone()))
                        .collect(),
                ),
            );
        }

        if options.recursive {
            map.insert("recursive".to_string(), serde_json::Value::Bool(true));
        }

        if let Some(hash) = options.hash_algorithm {
            map.insert(
                "hash".to_string(),
                serde_json::Value::String(
                    match hash {
                        HashAlgorithm::Sha256 => "sha256",
                        HashAlgorithm::Sha1 => "sha1",
                        HashAlgorithm::Md5 => "md5",
                    }
                    .to_string(),
                ),
            );
        }

        if let Some(filter) = &options.filter {
            map.insert("filter".to_string(), self.expr_to_json(filter)?);
        }

        if let Some(limit) = &options.limit {
            map.insert("limit".to_string(), self.expr_to_json(limit)?);
        }

        Ok(map)
    }

    fn convert_export_format(&self, format: ExportFormat) -> String {
        match format {
            ExportFormat::Json => "json".to_string(),
            ExportFormat::Csv => "csv".to_string(),
            ExportFormat::Xml => "xml".to_string(),
        }
    }

    fn convert_expression(&self, expr: &Expr) -> Result<serde_json::Value, Vec<Diagnostic>> {
        self.expr_to_json(expr)
    }

    fn expr_to_json(&self, expr: &Expr) -> Result<serde_json::Value, Vec<Diagnostic>> {
        match expr {
            Expr::Identifier(name, _) => Ok(serde_json::Value::String(format!("${}", name))),
            Expr::StringLiteral(s, _) => Ok(serde_json::Value::String(s.clone())),
            Expr::IntegerLiteral(n, _) => Ok(serde_json::Value::Number((*n).into())),
            Expr::FloatLiteral(f, _) => Ok(serde_json::Value::Number(
                serde_json::Number::from_f64(*f).unwrap_or(serde_json::Number::from(0)),
            )),
            Expr::BooleanLiteral(b, _) => Ok(serde_json::Value::Bool(*b)),
            Expr::BinaryOp {
                left, op, right, ..
            } => {
                let l = self.expr_to_json(left)?;
                let r = self.expr_to_json(right)?;
                Ok(serde_json::json!({
                    "op": format!("{:?}", op).to_lowercase(),
                    "left": l,
                    "right": r
                }))
            }
            Expr::UnaryOp { op, expr, .. } => {
                let e = self.expr_to_json(expr)?;
                Ok(serde_json::json!({
                    "op": format!("{:?}", op).to_lowercase(),
                    "expr": e
                }))
            }
            Expr::FieldAccess { object, field, .. } => {
                let obj = self.expr_to_json(object)?;
                Ok(serde_json::json!({
                    "field_access": {
                        "object": obj,
                        "field": field
                    }
                }))
            }
            Expr::Call {
                callee, arguments, ..
            } => {
                let mut args = Vec::new();
                for arg in arguments {
                    args.push(self.expr_to_json(arg)?);
                }
                Ok(serde_json::json!({
                    "call": {
                        "callee": self.expr_to_json(callee)?,
                        "arguments": args
                    }
                }))
            }
            Expr::ArrayLiteral(elements, _) => {
                let mut arr = Vec::new();
                for elem in elements {
                    arr.push(self.expr_to_json(elem)?);
                }
                Ok(serde_json::Value::Array(arr))
            }
            Expr::ObjectLiteral(fields, _) => {
                let mut map = serde_json::Map::new();
                for (key, value) in fields {
                    map.insert(key.clone(), self.expr_to_json(value)?);
                }
                Ok(serde_json::Value::Object(map))
            }
        }
    }

    fn add_error(&mut self, message: &str, span: Span) {
        self.diagnostics.push(Diagnostic::error(message, span));
    }
}

impl Default for SemanticAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use traceforge_ast::Severity;
    use traceforge_lexer::Lexer;
    use traceforge_parser::Parser;

    fn analyze_source(source: &str) -> (Option<traceforge_ir::IrInvestigation>, Vec<Diagnostic>) {
        let mut lexer = Lexer::new(source);
        let tokens = lexer.tokenize().unwrap();
        let mut parser = Parser::new(tokens);
        let (ast, parse_diags) = parser.parse_with_diagnostics();

        if !parse_diags.is_empty() {
            return (None, parse_diags);
        }

        let mut analyzer = SemanticAnalyzer::new();
        analyzer.analyze_with_diagnostics(ast.as_ref().unwrap())
    }

    #[test]
    fn test_valid_investigation() {
        let source = r#"
            investigation "test" {
                collect system_info
                collect processes {
                    pid
                    name
                    hash.sha256
                }
                export evidence "output.json"
            }
        "#;
        let (ir, diags) = analyze_source(source);
        assert!(diags.is_empty());
        assert!(ir.is_some());
        let ir = ir.unwrap();
        assert_eq!(ir.name, "test");
        assert!(ir
            .required_capabilities
            .contains(&Capability::SystemInfoRead));
        assert!(ir.required_capabilities.contains(&Capability::ProcessRead));
        assert!(ir.required_capabilities.contains(&Capability::FileHash));
    }

    #[test]
    fn test_missing_collect() {
        let source = r#"
            investigation "test" {
                export evidence "output.json"
            }
        "#;
        let (ir, diags) = analyze_source(source);
        assert!(ir.is_none());
        assert!(diags
            .iter()
            .any(|d| d.severity == Severity::Error && d.message.contains("collect")));
    }

    #[test]
    fn test_missing_export() {
        let source = r#"
            investigation "test" {
                collect system_info
            }
        "#;
        let (ir, diags) = analyze_source(source);
        assert!(ir.is_none());
        assert!(diags
            .iter()
            .any(|d| d.severity == Severity::Error && d.message.contains("export")));
    }

    #[test]
    fn test_duplicate_export() {
        let source = r#"
            investigation "test" {
                collect system_info
                export evidence "out1.json"
                export evidence "out2.json"
            }
        "#;
        let (ir, diags) = analyze_source(source);
        assert!(ir.is_none());
        assert!(diags.iter().any(|d| d.message.contains("Multiple export")));
    }

    #[test]
    fn test_files_collect_adds_capabilities() {
        let source = r#"
            investigation "test" {
                collect files "/tmp" {
                    hash.sha256
                    recursive true
                }
                export evidence "out.json"
            }
        "#;
        let (ir, diags) = analyze_source(source);
        assert!(diags.is_empty());
        let ir = ir.unwrap();
        assert!(ir
            .required_capabilities
            .contains(&Capability::FilesystemRead));
        assert!(ir.required_capabilities.contains(&Capability::FileHash));
    }
}
