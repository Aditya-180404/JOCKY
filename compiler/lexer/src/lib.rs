//! TraceForge Lexer - Tokenizes TraceForge source code

use std::fmt;
use thiserror::Error;
use traceforge_ast::{Span, Token, TokenKind};

#[derive(Debug, Error)]
pub enum LexerError {
    #[error("Unexpected character '{char}' at {span}")]
    UnexpectedChar { char: char, span: Span },
    #[error("Unterminated string literal at {span}")]
    UnterminatedString { span: Span },
    #[error("Invalid escape sequence at {span}")]
    InvalidEscape { span: Span },
    #[error("Invalid number format at {span}")]
    InvalidNumber { span: Span },
}

pub struct Lexer {
    input: Vec<char>,
    position: usize,
    line: usize,
    column: usize,
    start_line: usize,
    start_column: usize,
}

impl Lexer {
    pub fn new(input: &str) -> Self {
        Self {
            input: input.chars().collect(),
            position: 0,
            line: 1,
            column: 1,
            start_line: 1,
            start_column: 1,
        }
    }

    pub fn tokenize(&mut self) -> Result<Vec<Token>, LexerError> {
        let mut tokens = Vec::new();

        while !self.is_at_end() {
            self.start_line = self.line;
            self.start_column = self.column;

            if let Some(token) = self.next_token()? {
                tokens.push(token);
            }
        }

        tokens.push(Token::new(
            TokenKind::Eof,
            Span::new(self.start_line, self.start_column, self.line, self.column),
        ));

        Ok(tokens)
    }

    fn next_token(&mut self) -> Result<Option<Token>, LexerError> {
        let c = self.advance();

        match c {
            ' ' | '\r' | '\t' => Ok(None),
            '\n' => {
                self.line += 1;
                self.column = 1;
                Ok(None)
            }
            '(' => Ok(Some(self.make_token(TokenKind::LeftParen))),
            ')' => Ok(Some(self.make_token(TokenKind::RightParen))),
            '{' => Ok(Some(self.make_token(TokenKind::LeftBrace))),
            '}' => Ok(Some(self.make_token(TokenKind::RightBrace))),
            '[' => Ok(Some(self.make_token(TokenKind::LeftBracket))),
            ']' => Ok(Some(self.make_token(TokenKind::RightBracket))),
            ',' => Ok(Some(self.make_token(TokenKind::Comma))),
            '.' => Ok(Some(self.make_token(TokenKind::Dot))),
            ':' => Ok(Some(self.make_token(TokenKind::Colon))),
            ';' => Ok(Some(self.make_token(TokenKind::Semicolon))),
            '+' => Ok(Some(self.make_token(TokenKind::Plus))),
            '-' => Ok(Some(self.make_token(TokenKind::Minus))),
            '*' => Ok(Some(self.make_token(TokenKind::Star))),
            '/' => {
                if self.match_char('/') {
                    // Single-line comment
                    while !self.is_at_end() && self.peek() != '\n' {
                        self.advance();
                    }
                    Ok(None)
                } else if self.match_char('*') {
                    // Multi-line comment
                    self.skip_multiline_comment()?;
                    Ok(None)
                } else {
                    Ok(Some(self.make_token(TokenKind::Slash)))
                }
            }
            '=' => {
                if self.match_char('=') {
                    Ok(Some(self.make_token(TokenKind::EqualEqual)))
                } else {
                    Ok(Some(self.make_token(TokenKind::Equal)))
                }
            }
            '!' => {
                if self.match_char('=') {
                    Ok(Some(self.make_token(TokenKind::BangEqual)))
                } else {
                    Ok(Some(self.make_token(TokenKind::Bang)))
                }
            }
            '<' => {
                if self.match_char('=') {
                    Ok(Some(self.make_token(TokenKind::LessEqual)))
                } else {
                    Ok(Some(self.make_token(TokenKind::Less)))
                }
            }
            '>' => {
                if self.match_char('=') {
                    Ok(Some(self.make_token(TokenKind::GreaterEqual)))
                } else {
                    Ok(Some(self.make_token(TokenKind::Greater)))
                }
            }
            '"' => self.string_literal(),
            c if c.is_ascii_digit() => self.number(),
            c if c.is_ascii_alphabetic() || c == '_' => self.identifier(),
            _ => Err(LexerError::UnexpectedChar {
                char: c,
                span: Span::new(self.start_line, self.start_column, self.line, self.column),
            }),
        }
    }

    fn string_literal(&mut self) -> Result<Option<Token>, LexerError> {
        let mut value = String::new();

        while !self.is_at_end() && self.peek() != '"' {
            if self.peek() == '\n' {
                self.line += 1;
                self.column = 1;
            }

            if self.peek() == '\\' {
                self.advance(); // consume backslash
                let escaped = self.advance();
                match escaped {
                    'n' => value.push('\n'),
                    't' => value.push('\t'),
                    'r' => value.push('\r'),
                    '\\' => value.push('\\'),
                    '"' => value.push('"'),
                    '\'' => value.push('\''),
                    _ => {
                        return Err(LexerError::InvalidEscape {
                            span: Span::new(self.line, self.column - 1, self.line, self.column),
                        });
                    }
                }
            } else {
                value.push(self.advance());
            }
        }

        if self.is_at_end() {
            return Err(LexerError::UnterminatedString {
                span: Span::new(self.start_line, self.start_column, self.line, self.column),
            });
        }

        // Consume closing quote
        self.advance();

        Ok(Some(self.make_token_with_value(TokenKind::String(value))))
    }

    fn number(&mut self) -> Result<Option<Token>, LexerError> {
        let mut value = String::new();
        value.push(self.previous());

        while !self.is_at_end() && self.peek().is_ascii_digit() {
            value.push(self.advance());
        }

        // Check for decimal point
        if !self.is_at_end() && self.peek() == '.' && self.peek_next().is_ascii_digit() {
            value.push(self.advance()); // consume '.'
            while !self.is_at_end() && self.peek().is_ascii_digit() {
                value.push(self.advance());
            }
            let float_val: f64 = value.parse().map_err(|_| LexerError::InvalidNumber {
                span: Span::new(self.start_line, self.start_column, self.line, self.column),
            })?;
            Ok(Some(self.make_token_with_value(TokenKind::Float(float_val))))
        } else {
            let int_val: i64 = value.parse().map_err(|_| LexerError::InvalidNumber {
                span: Span::new(self.start_line, self.start_column, self.line, self.column),
            })?;
            Ok(Some(self.make_token_with_value(TokenKind::Integer(int_val))))
        }
    }

    fn identifier(&mut self) -> Result<Option<Token>, LexerError> {
        let mut value = String::new();
        value.push(self.previous());

        while !self.is_at_end() && (self.peek().is_ascii_alphanumeric() || self.peek() == '_') {
            value.push(self.advance());
        }

        let kind = match value.as_str() {
            "investigation" => TokenKind::Investigation,
            "collect" => TokenKind::Collect,
            "export" => TokenKind::Export,
            "filter" => TokenKind::Filter,
            "where" => TokenKind::Where,
            "limit" => TokenKind::Limit,
            "metadata" => TokenKind::Metadata,
            "hash" => TokenKind::Hash,
            "system_info" => TokenKind::SystemInfo,
            "processes" => TokenKind::Processes,
            "network_connections" => TokenKind::NetworkConnections,
            "files" => TokenKind::Files,
            "logs" => TokenKind::Logs,
            "evidence" => TokenKind::Evidence,
            "true" => TokenKind::True,
            "false" => TokenKind::False,
            "recursive" => TokenKind::Recursive,
            "sha256" => TokenKind::Sha256,
            "sha1" => TokenKind::Sha1,
            "md5" => TokenKind::Md5,
            "and" => TokenKind::And,
            "or" => TokenKind::Or,
            _ => TokenKind::Identifier(value),
        };

        Ok(Some(self.make_token(kind)))
    }

    fn skip_multiline_comment(&mut self) -> Result<(), LexerError> {
        let mut depth = 1;

        while !self.is_at_end() && depth > 0 {
            let c = self.advance();
            if c == '*' && self.peek() == '/' {
                self.advance();
                depth -= 1;
            } else if c == '/' && self.peek() == '*' {
                self.advance();
                depth += 1;
            } else if c == '\n' {
                self.line += 1;
                self.column = 1;
            }
        }

        if depth > 0 {
            Err(LexerError::UnexpectedChar {
                char: '*',
                span: Span::new(self.start_line, self.start_column, self.line, self.column),
            })
        } else {
            Ok(())
        }
    }

    fn make_token(&mut self, kind: TokenKind) -> Token {
        Token::new(
            kind,
            Span::new(self.start_line, self.start_column, self.line, self.column),
        )
    }

    fn make_token_with_value(&mut self, kind: TokenKind) -> Token {
        Token::new(
            kind,
            Span::new(self.start_line, self.start_column, self.line, self.column),
        )
    }

    fn advance(&mut self) -> char {
        let c = self.input[self.position];
        self.position += 1;
        self.column += 1;
        c
    }

    fn peek(&self) -> char {
        if self.position >= self.input.len() {
            '\0'
        } else {
            self.input[self.position]
        }
    }

    fn peek_next(&self) -> char {
        if self.position + 1 >= self.input.len() {
            '\0'
        } else {
            self.input[self.position + 1]
        }
    }

    fn previous(&self) -> char {
        self.input[self.position - 1]
    }

    fn match_char(&mut self, expected: char) -> bool {
        if self.is_at_end() || self.peek() != expected {
            false
        } else {
            self.advance();
            true
        }
    }

    fn is_at_end(&self) -> bool {
        self.position >= self.input.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize_simple() {
        let mut lexer = Lexer::new(r#"investigation "test" { collect system_info }"#);
        let tokens = lexer.tokenize().unwrap();

        assert!(matches!(tokens[0].kind, TokenKind::Investigation));
        assert!(matches!(tokens[1].kind, TokenKind::String(ref s) if s == "test"));
        assert!(matches!(tokens[2].kind, TokenKind::LeftBrace));
        assert!(matches!(tokens[3].kind, TokenKind::Collect));
        assert!(matches!(tokens[4].kind, TokenKind::SystemInfo));
        assert!(matches!(tokens[5].kind, TokenKind::RightBrace));
        assert!(matches!(tokens[6].kind, TokenKind::Eof));
    }

    #[test]
    fn test_tokenize_numbers() {
        let mut lexer = Lexer::new("42 3.14");
        let tokens = lexer.tokenize().unwrap();

        assert!(matches!(tokens[0].kind, TokenKind::Integer(42)));
        assert!(matches!(tokens[1].kind, TokenKind::Float(f) if (f - 3.14).abs() < f64::EPSILON));
    }

    #[test]
    fn test_tokenize_string_escapes() {
        let mut lexer = Lexer::new(r#""hello\nworld""#);
        let tokens = lexer.tokenize().unwrap();

        assert!(matches!(tokens[0].kind, TokenKind::String(ref s) if s == "hello\nworld"));
    }

    #[test]
    fn test_tokenize_comments() {
        let mut lexer = Lexer::new("collect system_info // comment\ncollect processes");
        let tokens = lexer.tokenize().unwrap();

        assert!(matches!(tokens[0].kind, TokenKind::Collect));
        assert!(matches!(tokens[1].kind, TokenKind::SystemInfo));
        assert!(matches!(tokens[2].kind, TokenKind::Collect));
        assert!(matches!(tokens[3].kind, TokenKind::Processes));
    }
}