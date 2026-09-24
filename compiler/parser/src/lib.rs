//! jockey Parser - Parses tokens into AST

use std::vec;
use thiserror::Error;
use jockey_ast::{
    BinaryOp, CollectOptions, CollectTarget, Diagnostic, ExportFormat, Expr, HashAlgorithm,
    Investigation, PipelineStage, Span, Stmt, Token, TokenKind, UnaryOp,
};
use jockey_lexer::LexerError;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Unexpected token {found:?} at {span}, expected {expected}")]
    UnexpectedToken {
        found: TokenKind,
        span: Span,
        expected: String,
    },
    #[error("Unexpected end of input at {span}, expected {expected}")]
    UnexpectedEof { span: Span, expected: String },
    #[error("Lexer error: {0}")]
    LexerError(#[from] LexerError),
    #[error("Invalid number: {message} at {span}")]
    InvalidNumber { message: String, span: Span },
}

pub struct Parser {
    tokens: Vec<Token>,
    current: usize,
    diagnostics: Vec<Diagnostic>,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            current: 0,
            diagnostics: Vec::new(),
        }
    }

    pub fn parse(&mut self) -> Result<Investigation, Vec<Diagnostic>> {
        let investigation = self.parse_investigation()?;

        if !self.diagnostics.is_empty() {
            let diags = std::mem::take(&mut self.diagnostics);
            return Err(diags);
        }

        Ok(investigation)
    }

    pub fn parse_with_diagnostics(&mut self) -> (Option<Investigation>, Vec<Diagnostic>) {
        let result = self.parse_investigation();
        let diags = std::mem::take(&mut self.diagnostics);

        match result {
            Ok(inv) => (Some(inv), diags),
            Err(mut e) => {
                e.extend(diags);
                (None, e)
            }
        }
    }

    fn parse_investigation(&mut self) -> Result<Investigation, Vec<Diagnostic>> {
        let start_span = self.current_token_span();

        self.consume(TokenKind::Investigation, "expected 'investigation'")?;

        // Accept either a string literal or identifier for investigation name
        let name = if self.check(TokenKind::String("".to_string())) {
            self.consume_string("expected investigation name")?
        } else {
            self.consume_identifier("expected investigation name")?
        };

        let mut metadata = Vec::new();
        if self.check(TokenKind::Metadata) {
            self.advance(); // consume 'metadata'
            metadata = self.parse_metadata_block()?;
        }

        self.consume(
            TokenKind::LeftBrace,
            "expected '{' after investigation name",
        )?;

        if self.check(TokenKind::Metadata) {
            self.advance();
            metadata = self.parse_metadata_block()?;
        }

        let mut target = None;
        if self.check(TokenKind::Target) {
            self.advance();
            target =
                Some(self.consume_identifier("expected target platform (e.g. windows, linux)")?);
        }

        let mut statements = Vec::new();
        while !self.check(TokenKind::RightBrace) && !self.check(TokenKind::Eof) {
            if let Some(stmt) = self.parse_statement()? {
                if let Stmt::Target(ref t, _) = stmt {
                    if target.is_none() {
                        target = Some(t.clone());
                    }
                }
                statements.push(stmt);
            }
        }

        let end_span = self
            .consume(TokenKind::RightBrace, "expected '}' to close investigation")?
            .span;

        Ok(Investigation {
            name,
            target,
            metadata,
            statements,
            span: start_span.merge(&end_span),
        })
    }

    fn parse_metadata_block(&mut self) -> Result<Vec<(String, Expr)>, Vec<Diagnostic>> {
        self.consume(TokenKind::LeftBrace, "expected '{' after 'metadata'")?;
        let mut metadata = Vec::new();

        while !self.check(TokenKind::RightBrace) && !self.check(TokenKind::Eof) {
            let key = self.consume_identifier("expected metadata key")?;
            if self.check(TokenKind::Colon) || self.check(TokenKind::Equal) {
                self.advance();
            } else {
                self.consume(TokenKind::Colon, "expected ':' or '=' after metadata key")?;
            }
            let value = self.parse_expression()?;
            metadata.push((key, value));

            if self.check(TokenKind::Comma) {
                self.advance();
            }
        }

        self.consume(TokenKind::RightBrace, "expected '}' to close metadata")?;
        Ok(metadata)
    }

    fn token_as_identifier(&self, kind: &TokenKind) -> Option<String> {
        match kind {
            TokenKind::Identifier(name) => Some(name.clone()),
            TokenKind::Processes => Some("processes".to_string()),
            TokenKind::SystemInfo => Some("system_info".to_string()),
            TokenKind::NetworkConnections => Some("network_connections".to_string()),
            TokenKind::Files => Some("files".to_string()),
            TokenKind::Logs => Some("logs".to_string()),
            TokenKind::Drivers => Some("drivers".to_string()),
            TokenKind::Timeline => Some("timeline".to_string()),
            TokenKind::MemoryRegions => Some("memory_regions".to_string()),
            TokenKind::Registry => Some("registry".to_string()),
            TokenKind::Artifacts => Some("artifacts".to_string()),
            TokenKind::Evidence => Some("evidence".to_string()),
            TokenKind::Target => Some("target".to_string()),
            _ => None,
        }
    }

    fn peek_is_equal(&self) -> bool {
        if self.current + 1 < self.tokens.len() {
            matches!(self.tokens[self.current + 1].kind, TokenKind::Equal)
        } else {
            false
        }
    }

    fn parse_statement(&mut self) -> Result<Option<Stmt>, Vec<Diagnostic>> {
        let token = self.current_token().clone();

        if self.peek_is_equal() {
            if let Some(name) = self.token_as_identifier(&token.kind) {
                let start_span = token.span;
                self.advance(); // consume identifier
                self.consume(TokenKind::Equal, "expected '='")?;
                let expression = self.parse_expression()?;
                let span = start_span.merge(&expression.span());
                return Ok(Some(Stmt::Assign {
                    variable: name,
                    expression,
                    span,
                }));
            }
        }

        match &token.kind {
            TokenKind::Target => self.parse_target_statement().map(Some),
            TokenKind::Collect => self.parse_collect_statement().map(Some),
            TokenKind::Export => self.parse_export_statement().map(Some),
            TokenKind::Filter => self.parse_filter_statement().map(Some),
            TokenKind::Where => self.parse_where_statement().map(Some),
            TokenKind::Limit => self.parse_limit_statement().map(Some),
            TokenKind::Metadata => self.parse_metadata_statement().map(Some),
            TokenKind::Evidence => self.parse_evidence_statement().map(Some),
            TokenKind::Identifier(name) => {
                let name = name.clone();
                let start_span = token.span;
                self.advance();
                if self.match_token(TokenKind::Equal) {
                    let expression = self.parse_expression()?;
                    let span = start_span.merge(&expression.span());
                    Ok(Some(Stmt::Assign {
                        variable: name,
                        expression,
                        span,
                    }))
                } else {
                    self.add_diagnostic(Diagnostic::error(
                        format!(
                            "Unexpected identifier '{}' in statement position, expected '='",
                            name
                        ),
                        start_span,
                    ));
                    self.synchronize();
                    Ok(None)
                }
            }
            _ => {
                self.add_diagnostic(Diagnostic::error(
                    format!("Unexpected token {:?} in statement position", token.kind),
                    token.span,
                ));
                self.synchronize();
                Ok(None)
            }
        }
    }

    fn parse_target_statement(&mut self) -> Result<Stmt, Vec<Diagnostic>> {
        let start_span = self.consume(TokenKind::Target, "expected 'target'")?.span;
        let target = self.consume_identifier("expected target platform (e.g. windows, linux)")?;
        let span = start_span.merge(&self.previous_token_span());
        Ok(Stmt::Target(target, span))
    }

    fn parse_evidence_statement(&mut self) -> Result<Stmt, Vec<Diagnostic>> {
        let start_span = self
            .consume(TokenKind::Evidence, "expected 'evidence'")?
            .span;
        let var_name = self.consume_identifier("expected variable name after 'evidence'")?;
        let mut stages = Vec::new();
        while self.match_token(TokenKind::Pipe) {
            let stage = self.parse_pipeline_stage()?;
            stages.push(stage);
        }
        let span = if let Some(last) = stages.last() {
            start_span.merge(&last.span())
        } else {
            start_span.merge(&self.previous_token_span())
        };
        Ok(Stmt::EvidencePipeline {
            variable: var_name,
            stages,
            span,
        })
    }

    fn parse_collect_statement(&mut self) -> Result<Stmt, Vec<Diagnostic>> {
        let start_span = self.consume(TokenKind::Collect, "expected 'collect'")?.span;

        let target = self.parse_collect_target()?;
        let options = self.parse_collect_options()?;

        let end_span = self.previous_token_span();
        Ok(Stmt::Collect {
            target,
            options,
            span: start_span.merge(&end_span),
        })
    }

    fn parse_collect_target(&mut self) -> Result<CollectTarget, Vec<Diagnostic>> {
        let token = self.current_token();

        match &token.kind {
            TokenKind::SystemInfo => {
                self.advance();
                Ok(CollectTarget::SystemInfo)
            }
            TokenKind::Processes => {
                self.advance();
                Ok(CollectTarget::Processes)
            }
            TokenKind::NetworkConnections => {
                self.advance();
                Ok(CollectTarget::NetworkConnections)
            }
            TokenKind::Drivers => {
                self.advance();
                Ok(CollectTarget::Drivers)
            }
            TokenKind::Timeline => {
                self.advance();
                let mut sources = Vec::new();
                if self.check(TokenKind::LeftBrace) {
                    self.advance();
                    while !self.check(TokenKind::RightBrace) && !self.check(TokenKind::Eof) {
                        let src = self.consume_identifier("expected timeline source event type")?;
                        sources.push(src);
                    }
                    self.consume(
                        TokenKind::RightBrace,
                        "expected '}' closing timeline sources",
                    )?;
                }
                Ok(CollectTarget::Timeline { sources })
            }
            TokenKind::MemoryRegions => {
                self.advance();
                Ok(CollectTarget::MemoryRegions)
            }
            TokenKind::Registry => {
                self.advance();
                let hive = if self.check(TokenKind::String("".to_string())) {
                    self.consume_string("expected registry hive")?
                } else {
                    "HKLM".to_string()
                };
                let key_path = if self.check(TokenKind::String("".to_string())) {
                    self.consume_string("expected registry key path")?
                } else {
                    "SOFTWARE".to_string()
                };
                Ok(CollectTarget::Registry { hive, key_path })
            }
            TokenKind::Artifacts => {
                self.advance();
                let artifact_type = if self.check(TokenKind::String("".to_string())) {
                    self.consume_string("expected artifact type")?
                } else {
                    "all".to_string()
                };
                let path = if self.check(TokenKind::String("".to_string())) {
                    self.consume_string("expected artifact path")?
                } else {
                    "".to_string()
                };
                Ok(CollectTarget::Artifacts {
                    artifact_type,
                    path,
                })
            }
            TokenKind::Files => {
                self.advance();
                let path = if self.check(TokenKind::String("".to_string())) {
                    self.consume_string("expected file path")?
                } else {
                    "/".to_string()
                };
                Ok(CollectTarget::Files { path })
            }
            TokenKind::Logs => {
                self.advance();
                let source = if self.check(TokenKind::String("".to_string())) {
                    self.consume_string("expected log source")?
                } else {
                    "system".to_string()
                };
                Ok(CollectTarget::Logs { source })
            }
            TokenKind::Evidence => {
                self.advance();
                let format = if self.check(TokenKind::String("".to_string())) {
                    self.consume_string("expected evidence format")?
                } else {
                    "json".to_string()
                };
                Ok(CollectTarget::Evidence { format })
            }
            _ => {
                self.add_diagnostic(Diagnostic::error(
                    format!("Expected collect target, found {:?}", token.kind),
                    token.span,
                ));
                self.synchronize();
                Err(vec![])
            }
        }
    }

    fn parse_collect_options(&mut self) -> Result<CollectOptions, Vec<Diagnostic>> {
        let mut options = CollectOptions::default();

        if self.check(TokenKind::LeftBrace) {
            self.advance(); // consume '{'

            while !self.check(TokenKind::RightBrace) && !self.check(TokenKind::Eof) {
                // Accept Identifier, Hash, Recursive as option names
                let key = if self.check(TokenKind::Hash) {
                    self.advance();
                    "hash".to_string()
                } else if self.check(TokenKind::Recursive) {
                    self.advance();
                    "recursive".to_string()
                } else {
                    self.consume_identifier("expected option name")?
                };

                match key.as_str() {
                    "recursive" => {
                        if self.check(TokenKind::Colon) {
                            self.advance();
                            options.recursive = self.consume_boolean("expected boolean value")?;
                        } else if self.check(TokenKind::True) || self.check(TokenKind::False) {
                            options.recursive = self.consume_boolean("expected boolean value")?;
                        } else {
                            options.recursive = true;
                        }
                    }
                    "hash" => {
                        // Check for hash.sha256 syntax (field access style)
                        if self.check(TokenKind::Dot) {
                            self.advance(); // consume '.'
                                            // After dot, could be identifier or keyword (sha256, sha1, md5)
                            let token = self.current_token().clone();
                            let algo = match token.kind {
                                TokenKind::Identifier(name) => {
                                    self.advance();
                                    name
                                }
                                TokenKind::Sha256 => {
                                    self.advance();
                                    "sha256".to_string()
                                }
                                TokenKind::Sha1 => {
                                    self.advance();
                                    "sha1".to_string()
                                }
                                TokenKind::Md5 => {
                                    self.advance();
                                    "md5".to_string()
                                }
                                _ => {
                                    self.add_diagnostic(Diagnostic::error(
                                        format!(
                                            "Expected hash algorithm after '.', found {:?}",
                                            token.kind
                                        ),
                                        token.span,
                                    ));
                                    self.advance();
                                    "sha256".to_string()
                                }
                            };
                            options.hash_algorithm = Some(match algo.as_str() {
                                "sha256" => HashAlgorithm::Sha256,
                                "sha1" => HashAlgorithm::Sha1,
                                "md5" => HashAlgorithm::Md5,
                                _ => HashAlgorithm::Sha256,
                            });
                        } else {
                            // Original hash: sha256 syntax
                            self.consume(TokenKind::Colon, "expected ':' after 'hash'")?;
                            options.hash_algorithm = Some(self.parse_hash_algorithm()?);
                        }
                    }
                    "filter" => {
                        self.consume(TokenKind::Colon, "expected ':' after 'filter'")?;
                        options.filter = Some(self.parse_expression()?);
                    }
                    "limit" => {
                        self.consume(TokenKind::Colon, "expected ':' after 'limit'")?;
                        options.limit = Some(self.parse_expression()?);
                    }
                    field_name => {
                        // Collect field names for processes, etc.
                        options.fields.push(field_name.to_string());
                        if self.check(TokenKind::Colon) {
                            self.advance(); // consume ':'
                                            // Could parse field-specific options here
                        }
                    }
                }

                // Comma is optional - allow both comma-separated and newline-separated
                if !self.check(TokenKind::RightBrace)
                    && !self.check(TokenKind::Eof)
                    && self.check(TokenKind::Comma)
                {
                    self.advance(); // consume comma
                }
            }

            self.consume(
                TokenKind::RightBrace,
                "expected '}' to close collect options",
            )?;
        }

        Ok(options)
    }

    fn parse_hash_algorithm(&mut self) -> Result<HashAlgorithm, Vec<Diagnostic>> {
        let token = self.current_token();

        match &token.kind {
            TokenKind::Sha256 => {
                self.advance();
                Ok(HashAlgorithm::Sha256)
            }
            TokenKind::Sha1 => {
                self.advance();
                Ok(HashAlgorithm::Sha1)
            }
            TokenKind::Md5 => {
                self.advance();
                Ok(HashAlgorithm::Md5)
            }
            _ => {
                self.add_diagnostic(Diagnostic::error(
                    format!("Expected hash algorithm, found {:?}", token.kind),
                    token.span,
                ));
                self.advance();
                Ok(HashAlgorithm::Sha256)
            }
        }
    }

    fn parse_export_statement(&mut self) -> Result<Stmt, Vec<Diagnostic>> {
        let start_span = self.consume(TokenKind::Export, "expected 'export'")?.span;

        self.consume(TokenKind::Evidence, "expected 'evidence' after 'export'")?;

        // Check if next token is a string - could be format or path
        let format = if self.check(TokenKind::String("".to_string())) {
            // Peek at the string value to determine if it's a format or path
            let token = self.current_token().clone();
            if let TokenKind::String(s) = &token.kind {
                // If it looks like a file path (contains . or /), treat as path
                if s.contains('.') || s.contains('/') || s.contains('\\') {
                    ExportFormat::Json
                } else {
                    // Otherwise treat as format
                    self.advance();
                    match s.to_lowercase().as_str() {
                        "json" => ExportFormat::Json,
                        "csv" => ExportFormat::Csv,
                        "xml" => ExportFormat::Xml,
                        _ => ExportFormat::Json,
                    }
                }
            } else {
                ExportFormat::Json
            }
        } else {
            ExportFormat::Json
        };

        let path = self.consume_string("expected export path")?;

        let end_span = self.previous_token_span();
        Ok(Stmt::Export {
            format,
            path,
            span: start_span.merge(&end_span),
        })
    }

    fn parse_filter_statement(&mut self) -> Result<Stmt, Vec<Diagnostic>> {
        let start_span = self.consume(TokenKind::Filter, "expected 'filter'")?.span;
        let condition = self.parse_expression()?;
        let end_span = self.previous_token_span();
        Ok(Stmt::Filter {
            condition,
            span: start_span.merge(&end_span),
        })
    }

    fn parse_where_statement(&mut self) -> Result<Stmt, Vec<Diagnostic>> {
        let start_span = self.consume(TokenKind::Where, "expected 'where'")?.span;
        let condition = self.parse_expression()?;
        let end_span = self.previous_token_span();
        Ok(Stmt::Where {
            condition,
            span: start_span.merge(&end_span),
        })
    }

    fn parse_limit_statement(&mut self) -> Result<Stmt, Vec<Diagnostic>> {
        let start_span = self.consume(TokenKind::Limit, "expected 'limit'")?.span;
        let count = self.parse_expression()?;
        let end_span = self.previous_token_span();
        Ok(Stmt::Limit {
            count,
            span: start_span.merge(&end_span),
        })
    }

    fn parse_metadata_statement(&mut self) -> Result<Stmt, Vec<Diagnostic>> {
        let start_span = self
            .consume(TokenKind::Metadata, "expected 'metadata'")?
            .span;
        let metadata = self.parse_metadata_block()?;
        let end_span = self.previous_token_span();
        Ok(Stmt::Metadata(metadata, start_span.merge(&end_span)))
    }

    fn parse_expression(&mut self) -> Result<Expr, Vec<Diagnostic>> {
        let mut expr = self.parse_or()?;

        if self.check(TokenKind::Pipe) {
            let mut stages = Vec::new();
            while self.match_token(TokenKind::Pipe) {
                let stage = self.parse_pipeline_stage()?;
                stages.push(stage);
            }
            let span = if let Some(last) = stages.last() {
                expr.span().merge(&last.span())
            } else {
                expr.span()
            };
            expr = Expr::Pipeline {
                source: Box::new(expr),
                stages,
                span,
            };
        }

        Ok(expr)
    }

    fn parse_pipeline_stage(&mut self) -> Result<PipelineStage, Vec<Diagnostic>> {
        let token = self.current_token().clone();
        match &token.kind {
            TokenKind::Where => {
                self.advance();
                let cond = self.parse_or()?;
                let span = token.span.merge(&cond.span());
                Ok(PipelineStage::Where(cond, span))
            }
            TokenKind::Filter => {
                self.advance();
                let cond = self.parse_or()?;
                let span = token.span.merge(&cond.span());
                Ok(PipelineStage::Filter(cond, span))
            }
            TokenKind::Limit => {
                self.advance();
                let count = self.parse_or()?;
                let span = token.span.merge(&count.span());
                Ok(PipelineStage::Limit(count, span))
            }
            TokenKind::Hash => {
                self.advance();
                let algo_token = self.current_token().clone();
                let (algo, algo_span) = match algo_token.kind {
                    TokenKind::Sha256 => (HashAlgorithm::Sha256, algo_token.span),
                    TokenKind::Sha1 => (HashAlgorithm::Sha1, algo_token.span),
                    TokenKind::Md5 => (HashAlgorithm::Md5, algo_token.span),
                    _ => {
                        self.add_diagnostic(Diagnostic::error(
                            "Expected hash algorithm (sha256, sha1, md5)",
                            algo_token.span,
                        ));
                        (HashAlgorithm::Sha256, algo_token.span)
                    }
                };
                self.advance();
                let span = token.span.merge(&algo_span);
                Ok(PipelineStage::Hash(algo, span))
            }
            TokenKind::Timeline => {
                self.advance();
                Ok(PipelineStage::Timeline(token.span))
            }
            TokenKind::Export => {
                self.advance();
                let path = self.consume_string("expected export file path")?;
                let span = token.span.merge(&self.previous_token_span());
                Ok(PipelineStage::Export(path, span))
            }
            _ => {
                self.add_diagnostic(Diagnostic::error(
                    format!("Unexpected pipeline stage '{:?}'", token.kind),
                    token.span,
                ));
                Err(vec![])
            }
        }
    }

    fn parse_or(&mut self) -> Result<Expr, Vec<Diagnostic>> {
        let mut expr = self.parse_and()?;

        while self.match_token(TokenKind::Or) {
            let op = BinaryOp::Or;
            let right = self.parse_and()?;
            let span = expr.span().merge(&right.span());
            expr = Expr::BinaryOp {
                left: Box::new(expr),
                op,
                right: Box::new(right),
                span,
            };
        }

        Ok(expr)
    }

    fn parse_and(&mut self) -> Result<Expr, Vec<Diagnostic>> {
        let mut expr = self.parse_equality()?;

        while self.match_token(TokenKind::And) {
            let op = BinaryOp::And;
            let right = self.parse_equality()?;
            let span = expr.span().merge(&right.span());
            expr = Expr::BinaryOp {
                left: Box::new(expr),
                op,
                right: Box::new(right),
                span,
            };
        }

        Ok(expr)
    }

    fn parse_equality(&mut self) -> Result<Expr, Vec<Diagnostic>> {
        let mut expr = self.parse_comparison()?;

        while self.match_any(&[TokenKind::EqualEqual, TokenKind::BangEqual]) {
            let op = if self.previous_token_kind() == TokenKind::EqualEqual {
                BinaryOp::Equal
            } else {
                BinaryOp::NotEqual
            };
            let right = self.parse_comparison()?;
            let span = expr.span().merge(&right.span());
            expr = Expr::BinaryOp {
                left: Box::new(expr),
                op,
                right: Box::new(right),
                span,
            };
        }

        Ok(expr)
    }

    fn parse_comparison(&mut self) -> Result<Expr, Vec<Diagnostic>> {
        let mut expr = self.parse_term()?;

        while self.match_any(&[
            TokenKind::Greater,
            TokenKind::GreaterEqual,
            TokenKind::Less,
            TokenKind::LessEqual,
            TokenKind::Contains,
        ]) {
            let op = match self.previous_token_kind() {
                TokenKind::Greater => BinaryOp::Greater,
                TokenKind::GreaterEqual => BinaryOp::GreaterEqual,
                TokenKind::Less => BinaryOp::Less,
                TokenKind::LessEqual => BinaryOp::LessEqual,
                TokenKind::Contains => BinaryOp::Contains,
                _ => unreachable!(),
            };
            let right = self.parse_term()?;
            let span = expr.span().merge(&right.span());
            expr = Expr::BinaryOp {
                left: Box::new(expr),
                op,
                right: Box::new(right),
                span,
            };
        }

        Ok(expr)
    }

    fn parse_term(&mut self) -> Result<Expr, Vec<Diagnostic>> {
        let mut expr = self.parse_factor()?;

        while self.match_any(&[TokenKind::Plus, TokenKind::Minus]) {
            let op = if self.previous_token_kind() == TokenKind::Plus {
                BinaryOp::Add
            } else {
                BinaryOp::Subtract
            };
            let right = self.parse_factor()?;
            let span = expr.span().merge(&right.span());
            expr = Expr::BinaryOp {
                left: Box::new(expr),
                op,
                right: Box::new(right),
                span,
            };
        }

        Ok(expr)
    }

    fn parse_factor(&mut self) -> Result<Expr, Vec<Diagnostic>> {
        let mut expr = self.parse_unary()?;

        while self.match_any(&[TokenKind::Star, TokenKind::Slash]) {
            let op = if self.previous_token_kind() == TokenKind::Star {
                BinaryOp::Multiply
            } else {
                BinaryOp::Divide
            };
            let right = self.parse_unary()?;
            let span = expr.span().merge(&right.span());
            expr = Expr::BinaryOp {
                left: Box::new(expr),
                op,
                right: Box::new(right),
                span,
            };
        }

        Ok(expr)
    }

    fn parse_unary(&mut self) -> Result<Expr, Vec<Diagnostic>> {
        if self.match_any(&[TokenKind::Bang, TokenKind::Minus]) {
            let op = if self.previous_token_kind() == TokenKind::Bang {
                UnaryOp::Not
            } else {
                UnaryOp::Minus
            };
            let expr = self.parse_unary()?;
            let span = self.previous_token_span().merge(&expr.span());
            return Ok(Expr::UnaryOp {
                op,
                expr: Box::new(expr),
                span,
            });
        }

        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, Vec<Diagnostic>> {
        let token = self.current_token().clone();

        match token.kind {
            TokenKind::Collect => {
                let start_span = self.consume(TokenKind::Collect, "expected 'collect'")?.span;
                let target = self.parse_collect_target()?;
                let options = self.parse_collect_options()?;
                let span = start_span.merge(&self.previous_token_span());
                Ok(Expr::Collect {
                    target,
                    options: Box::new(options),
                    span,
                })
            }
            TokenKind::True => {
                self.advance();
                Ok(Expr::BooleanLiteral(true, token.span))
            }
            TokenKind::False => {
                self.advance();
                Ok(Expr::BooleanLiteral(false, token.span))
            }
            TokenKind::Integer(n) => {
                self.advance();
                Ok(Expr::IntegerLiteral(n, token.span))
            }
            TokenKind::Float(f) => {
                self.advance();
                Ok(Expr::FloatLiteral(f, token.span))
            }
            TokenKind::String(s) => {
                self.advance();
                Ok(Expr::StringLiteral(s, token.span))
            }
            TokenKind::Identifier(name) => {
                self.advance();

                let mut expr = Expr::Identifier(name, token.span);

                // Chained field access e.g. parent.name or hash.sha256
                while self.match_token(TokenKind::Dot) {
                    let field = self.consume_identifier("expected field name after '.'")?;
                    let span = expr.span().merge(&self.previous_token_span());
                    expr = Expr::FieldAccess {
                        object: Box::new(expr),
                        field,
                        span,
                    };
                }

                if self.match_token(TokenKind::LeftParen) {
                    let mut args = Vec::new();
                    if !self.check(TokenKind::RightParen) {
                        loop {
                            args.push(self.parse_expression()?);
                            if !self.match_token(TokenKind::Comma) {
                                break;
                            }
                        }
                    }
                    self.consume(TokenKind::RightParen, "expected ')' after arguments")?;
                    return Ok(Expr::Call {
                        callee: Box::new(expr),
                        arguments: args,
                        span: token.span.merge(&self.previous_token_span()),
                    });
                }

                Ok(expr)
            }
            TokenKind::LeftParen => {
                self.advance();
                let expr = self.parse_expression()?;
                self.consume(TokenKind::RightParen, "expected ')' after expression")?;
                Ok(expr)
            }
            TokenKind::LeftBracket => {
                self.advance();
                let mut elements = Vec::new();
                if !self.check(TokenKind::RightBracket) {
                    loop {
                        elements.push(self.parse_expression()?);
                        if !self.match_token(TokenKind::Comma) {
                            break;
                        }
                    }
                }
                let end_span = self.consume(TokenKind::RightBracket, "expected ']'")?.span;
                Ok(Expr::ArrayLiteral(elements, token.span.merge(&end_span)))
            }
            TokenKind::LeftBrace => {
                self.advance();
                let mut fields = Vec::new();
                if !self.check(TokenKind::RightBrace) {
                    loop {
                        let key = self.consume_identifier("expected object key")?;
                        self.consume(TokenKind::Colon, "expected ':' after object key")?;
                        let value = self.parse_expression()?;
                        fields.push((key, value));
                        if !self.match_token(TokenKind::Comma) {
                            break;
                        }
                    }
                }
                let end_span = self.consume(TokenKind::RightBrace, "expected '}'")?.span;
                Ok(Expr::ObjectLiteral(fields, token.span.merge(&end_span)))
            }
            ref kind => {
                if let Some(name) = self.token_as_identifier(kind) {
                    self.advance();
                    let mut expr = Expr::Identifier(name, token.span);

                    // Chained field access e.g. parent.name
                    while self.match_token(TokenKind::Dot) {
                        let field = self.consume_identifier("expected field name after '.'")?;
                        let span = expr.span().merge(&self.previous_token_span());
                        expr = Expr::FieldAccess {
                            object: Box::new(expr),
                            field,
                            span,
                        };
                    }

                    return Ok(expr);
                }

                self.add_diagnostic(Diagnostic::error(
                    format!("Unexpected token {:?} in expression", token.kind),
                    token.span,
                ));
                self.synchronize();
                Err(vec![])
            }
        }
    }

    // Helper methods
    fn current_token(&self) -> &Token {
        &self.tokens[self.current]
    }

    fn current_token_span(&self) -> Span {
        self.tokens[self.current].span
    }

    fn previous_token_span(&self) -> Span {
        if self.current > 0 {
            self.tokens[self.current - 1].span
        } else {
            self.tokens[0].span
        }
    }

    fn previous_token_kind(&self) -> TokenKind {
        if self.current > 0 {
            self.tokens[self.current - 1].kind.clone()
        } else {
            TokenKind::Eof
        }
    }

    fn advance(&mut self) -> &Token {
        if !self.check(TokenKind::Eof) {
            self.current += 1;
        }
        &self.tokens[self.current - 1]
    }

    fn check(&self, kind: TokenKind) -> bool {
        if self.current >= self.tokens.len() {
            false
        } else {
            std::mem::discriminant(&self.tokens[self.current].kind) == std::mem::discriminant(&kind)
        }
    }

    fn match_token(&mut self, kind: TokenKind) -> bool {
        if self.check(kind) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn match_any(&mut self, kinds: &[TokenKind]) -> bool {
        for kind in kinds {
            if self.check(kind.clone()) {
                self.advance();
                return true;
            }
        }
        false
    }

    fn consume(&mut self, kind: TokenKind, message: &str) -> Result<&Token, Vec<Diagnostic>> {
        if self.check(kind) {
            Ok(self.advance())
        } else {
            let token = self.current_token();
            self.add_diagnostic(Diagnostic::error(
                format!("{} at {}", message, token.span),
                token.span,
            ));
            Err(self.diagnostics.clone())
        }
    }

    fn consume_identifier(&mut self, message: &str) -> Result<String, Vec<Diagnostic>> {
        let token = self.current_token().clone();
        if let Some(name) = self.token_as_identifier(&token.kind) {
            self.advance();
            Ok(name)
        } else {
            self.add_diagnostic(Diagnostic::error(
                format!("{} at {}", message, token.span),
                token.span,
            ));
            Err(self.diagnostics.clone())
        }
    }

    fn consume_string(&mut self, message: &str) -> Result<String, Vec<Diagnostic>> {
        let token = self.current_token().clone();
        if let TokenKind::String(s) = token.kind {
            self.advance();
            Ok(s)
        } else {
            self.add_diagnostic(Diagnostic::error(
                format!("{} at {}", message, token.span),
                token.span,
            ));
            Err(self.diagnostics.clone())
        }
    }

    fn consume_boolean(&mut self, message: &str) -> Result<bool, Vec<Diagnostic>> {
        let token = self.current_token().clone();
        match token.kind {
            TokenKind::True => {
                self.advance();
                Ok(true)
            }
            TokenKind::False => {
                self.advance();
                Ok(false)
            }
            _ => {
                self.add_diagnostic(Diagnostic::error(
                    format!("{} at {}", message, token.span),
                    token.span,
                ));
                Err(self.diagnostics.clone())
            }
        }
    }

    fn add_diagnostic(&mut self, diagnostic: Diagnostic) {
        self.diagnostics.push(diagnostic);
    }

    fn synchronize(&mut self) {
        self.advance();

        while !self.check(TokenKind::Eof) {
            if self.previous_token_kind() == TokenKind::Semicolon
                || self.previous_token_kind() == TokenKind::RightBrace
            {
                return;
            }

            match self.current_token().kind {
                TokenKind::Collect
                | TokenKind::Export
                | TokenKind::Filter
                | TokenKind::Where
                | TokenKind::Limit
                | TokenKind::Metadata
                | TokenKind::Investigation => return,
                _ => {}
            }

            self.advance();
        }
    }
}

// Extension trait for Expr to get span
trait ExprSpan {
    fn span(&self) -> Span;
}

impl ExprSpan for Expr {
    fn span(&self) -> Span {
        match self {
            Expr::Identifier(_, span) => *span,
            Expr::StringLiteral(_, span) => *span,
            Expr::IntegerLiteral(_, span) => *span,
            Expr::FloatLiteral(_, span) => *span,
            Expr::BooleanLiteral(_, span) => *span,
            Expr::BinaryOp { span, .. } => *span,
            Expr::UnaryOp { span, .. } => *span,
            Expr::FieldAccess { span, .. } => *span,
            Expr::Call { span, .. } => *span,
            Expr::ArrayLiteral(_, span) => *span,
            Expr::ObjectLiteral(_, span) => *span,
            Expr::Pipeline { span, .. } => *span,
            Expr::Collect { span, .. } => *span,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jockey_lexer::Lexer;

    fn parse_source(source: &str) -> (Option<Investigation>, Vec<Diagnostic>) {
        let mut lexer = Lexer::new(source);
        let tokens = lexer.tokenize().unwrap();
        let mut parser = Parser::new(tokens);
        parser.parse_with_diagnostics()
    }

    #[test]
    fn test_parse_simple_investigation() {
        let source = r#"
            investigation "test" {
                collect system_info
                collect processes
                export evidence "output.json"
            }
        "#;
        let (inv, diags) = parse_source(source);
        assert!(diags.is_empty());
        assert!(inv.is_some());
        let inv = inv.unwrap();
        assert_eq!(inv.name, "test");
        assert_eq!(inv.statements.len(), 3);
    }

    #[test]
    fn test_parse_collect_with_options() {
        let source = r#"
            investigation "test" {
                collect processes {
                    pid
                    name
                    command_line
                    hash.sha256
                }
            }
        "#;
        let (inv, diags) = parse_source(source);
        assert!(diags.is_empty());
        let inv = inv.unwrap();
        if let Stmt::Collect { options, .. } = &inv.statements[0] {
            assert_eq!(options.fields, vec!["pid", "name", "command_line"]);
            assert_eq!(options.hash_algorithm, Some(HashAlgorithm::Sha256));
        }
    }

    #[test]
    fn test_parse_filter_where_limit() {
        let source = r#"
            investigation "test" {
                collect processes
                filter pid > 100
                where name == "malware.exe"
                limit 10
            }
        "#;
        let (inv, diags) = parse_source(source);
        assert!(diags.is_empty());
        let inv = inv.unwrap();
        assert_eq!(inv.statements.len(), 4);
    }

    #[test]
    fn test_parse_metadata() {
        let source = r#"
            investigation "test" {
                metadata {
                    author: "analyst"
                    version: "1.0"
                }
                collect system_info
            }
        "#;
        let (inv, diags) = parse_source(source);
        assert!(diags.is_empty());
        let inv = inv.unwrap();
        assert_eq!(inv.metadata.len(), 2);
    }

    #[test]
    fn test_parse_full_pipeline_investigation() {
        let source = r#"
            investigation "process_triage" {
                target windows

                processes = collect processes {
                    pid
                    name
                    parent
                    command_line
                    executable
                    start_time
                    hash.sha256
                }

                suspicious = processes
                    | where command_line contains "powershell"
                    | where parent.name == "winword.exe"

                evidence suspicious
                    | hash sha256
                    | timeline
                    | export "suspicious-processes.json"
            }
        "#;
        let (inv, diags) = parse_source(source);
        assert!(diags.is_empty(), "diags: {:?}", diags);
        let inv = inv.unwrap();
        assert_eq!(inv.name, "process_triage");
        assert_eq!(inv.target, Some("windows".to_string()));
        // target is consumed as investigation header, leaving 3 body statements:
        //   1. processes = collect processes { ... }
        //   2. suspicious = processes | where ... | where ...
        //   3. evidence suspicious | hash sha256 | timeline | export "..."
        assert_eq!(inv.statements.len(), 3);
    }
}
