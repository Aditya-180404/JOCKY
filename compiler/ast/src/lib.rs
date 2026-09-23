//! TraceForge AST - Abstract Syntax Tree definitions

use serde::{Deserialize, Serialize};
use std::fmt;

/// Source code span/location information
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

impl Span {
    pub fn new(start_line: usize, start_column: usize, end_line: usize, end_column: usize) -> Self {
        Self {
            start_line,
            start_column,
            end_line,
            end_column,
        }
    }

    pub fn merge(&self, other: &Span) -> Span {
        Span {
            start_line: self.start_line,
            start_column: self.start_column,
            end_line: other.end_line,
            end_column: other.end_column,
        }
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start_line == self.end_line {
            write!(
                f,
                "{}:{}-{}",
                self.start_line, self.start_column, self.end_column
            )
        } else {
            write!(
                f,
                "{}:{}-{}:{}",
                self.start_line, self.start_column, self.end_line, self.end_column
            )
        }
    }
}

/// Token kinds recognized by the lexer
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TokenKind {
    // Keywords
    Investigation,
    Target,
    Collect,
    Export,
    Filter,
    Where,
    Limit,
    Metadata,
    Hash,
    SystemInfo,
    Processes,
    NetworkConnections,
    Files,
    Logs,
    Evidence,
    Drivers,
    Timeline,
    Recursive,
    Sha256,
    Sha1,
    Md5,
    And,
    Or,
    Contains,

    // Literals
    Identifier(String),
    String(String),
    Integer(i64),
    Float(f64),
    True,
    False,

    // Symbols
    LeftParen,
    RightParen,
    LeftBrace,
    RightBrace,
    LeftBracket,
    RightBracket,
    Comma,
    Dot,
    Colon,
    Semicolon,
    Plus,
    Minus,
    Star,
    Slash,
    Equal,
    EqualEqual,
    Bang,
    BangEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Pipe,

    // Special
    Eof,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

impl Token {
    pub fn new(kind: TokenKind, span: Span) -> Self {
        Self { kind, span }
    }
}

/// Pipeline processing stage node
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PipelineStage {
    Where(Expr, Span),
    Filter(Expr, Span),
    Hash(HashAlgorithm, Span),
    Timeline(Span),
    Export(String, Span),
    Limit(Expr, Span),
}

impl PipelineStage {
    pub fn span(&self) -> Span {
        match self {
            PipelineStage::Where(_, s) => *s,
            PipelineStage::Filter(_, s) => *s,
            PipelineStage::Hash(_, s) => *s,
            PipelineStage::Timeline(s) => *s,
            PipelineStage::Export(_, s) => *s,
            PipelineStage::Limit(_, s) => *s,
        }
    }
}

/// Expression nodes
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Expr {
    Identifier(String, Span),
    StringLiteral(String, Span),
    IntegerLiteral(i64, Span),
    FloatLiteral(f64, Span),
    BooleanLiteral(bool, Span),
    BinaryOp {
        left: Box<Expr>,
        op: BinaryOp,
        right: Box<Expr>,
        span: Span,
    },
    UnaryOp {
        op: UnaryOp,
        expr: Box<Expr>,
        span: Span,
    },
    FieldAccess {
        object: Box<Expr>,
        field: String,
        span: Span,
    },
    Call {
        callee: Box<Expr>,
        arguments: Vec<Expr>,
        span: Span,
    },
    ArrayLiteral(Vec<Expr>, Span),
    ObjectLiteral(Vec<(String, Expr)>, Span),
    Pipeline {
        source: Box<Expr>,
        stages: Vec<PipelineStage>,
        span: Span,
    },
    Collect {
        target: CollectTarget,
        options: Box<CollectOptions>,
        span: Span,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryOp {
    Add,
    Subtract,
    Multiply,
    Divide,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    And,
    Or,
    Contains,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnaryOp {
    Not,
    Minus,
}

/// Statement nodes
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Stmt {
    Target(String, Span),
    Collect {
        target: CollectTarget,
        options: CollectOptions,
        span: Span,
    },
    Export {
        format: ExportFormat,
        path: String,
        span: Span,
    },
    Filter {
        condition: Expr,
        span: Span,
    },
    Where {
        condition: Expr,
        span: Span,
    },
    Limit {
        count: Expr,
        span: Span,
    },
    Metadata(Vec<(String, Expr)>, Span),
    Assign {
        variable: String,
        expression: Expr,
        span: Span,
    },
    EvidencePipeline {
        variable: String,
        stages: Vec<PipelineStage>,
        span: Span,
    },
}

impl Stmt {
    pub fn span(&self) -> Span {
        match self {
            Stmt::Target(_, span) => *span,
            Stmt::Collect { span, .. } => *span,
            Stmt::Export { span, .. } => *span,
            Stmt::Filter { span, .. } => *span,
            Stmt::Where { span, .. } => *span,
            Stmt::Limit { span, .. } => *span,
            Stmt::Metadata(_, span) => *span,
            Stmt::Assign { span, .. } => *span,
            Stmt::EvidencePipeline { span, .. } => *span,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CollectTarget {
    SystemInfo,
    Processes,
    NetworkConnections,
    Files { path: String },
    Logs { source: String },
    Evidence { format: String },
    Drivers,
    Timeline { sources: Vec<String> },
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CollectOptions {
    pub fields: Vec<String>,
    pub recursive: bool,
    pub hash_algorithm: Option<HashAlgorithm>,
    pub filter: Option<Expr>,
    pub limit: Option<Expr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Sha256,
    Sha1,
    Md5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportFormat {
    Json,
    Csv,
    Xml,
}

/// Investigation (top-level program)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Investigation {
    pub name: String,
    pub target: Option<String>,
    pub metadata: Vec<(String, Expr)>,
    pub statements: Vec<Stmt>,
    pub span: Span,
}

/// Diagnostic severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Error,
    Warning,
    Info,
    Hint,
}

/// Diagnostic message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: Severity,
    pub message: String,
    pub span: Option<Span>,
    pub code: Option<String>,
}

impl Diagnostic {
    pub fn error(message: impl Into<String>, span: Span) -> Self {
        Self {
            severity: Severity::Error,
            message: message.into(),
            span: Some(span),
            code: None,
        }
    }

    pub fn warning(message: impl Into<String>, span: Span) -> Self {
        Self {
            severity: Severity::Warning,
            message: message.into(),
            span: Some(span),
            code: None,
        }
    }

    pub fn info(message: impl Into<String>, span: Span) -> Self {
        Self {
            severity: Severity::Info,
            message: message.into(),
            span: Some(span),
            code: None,
        }
    }
}

/// Capability required by a tool
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    ProcessRead,
    NetworkRead,
    FilesystemRead,
    LogRead,
    SystemInfoRead,
    FileHash,
    DriverRead,
    TimelineRead,
}

impl Capability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::ProcessRead => "PROCESS_READ",
            Capability::NetworkRead => "NETWORK_READ",
            Capability::FilesystemRead => "FILESYSTEM_READ",
            Capability::LogRead => "LOG_READ",
            Capability::SystemInfoRead => "SYSTEM_INFO_READ",
            Capability::FileHash => "FILE_HASH",
            Capability::DriverRead => "DRIVER_READ",
            Capability::TimelineRead => "TIMELINE_READ",
        }
    }
}

impl std::str::FromStr for Capability {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "PROCESS_READ" => Ok(Capability::ProcessRead),
            "NETWORK_READ" => Ok(Capability::NetworkRead),
            "FILESYSTEM_READ" => Ok(Capability::FilesystemRead),
            "LOG_READ" => Ok(Capability::LogRead),
            "SYSTEM_INFO_READ" => Ok(Capability::SystemInfoRead),
            "FILE_HASH" => Ok(Capability::FileHash),
            "DRIVER_READ" => Ok(Capability::DriverRead),
            "TIMELINE_READ" => Ok(Capability::TimelineRead),
            _ => Err(()),
        }
    }
}
